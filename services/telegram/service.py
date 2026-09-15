"""Private Telegram login and read-only MCP, reachable only through Console.

The Console authenticates every browser and sandbox request, checks the DM
owner, then replaces the service credential and owner header. No agent receives
a Telegram session, login QR, password, or service credential.
"""

import asyncio
import base64
import hmac
import io
import json
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import qrcode
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from telethon import TelegramClient, errors, utils
from telethon.sessions import StringSession

from store import SessionStore, validate_owner

MAX_BODY = 64 * 1024
MAX_PENDING = 64
LOGIN_TTL = 300


@dataclass
class Login:
    client: object
    image: str
    expires: float
    phase: str = "waiting"
    task: asyncio.Task | None = None


class TelegramAccounts:
    def __init__(self, store, client_factory):
        self.store = store
        self.client_factory = client_factory
        self.pending = {}
        self.locks = {}

    def lock(self, owner):
        return self.locks.setdefault(validate_owner(owner), asyncio.Lock())

    async def status(self, owner):
        async with self.lock(owner):
            return self._status(owner)

    def _status(self, owner):
        if self.store.get(owner):
            return {"phase": "connected"}
        login = self.pending.get(owner)
        if not login:
            return {"phase": "disconnected"}
        body = {"phase": login.phase}
        if login.phase == "waiting":
            body["qr_image"] = login.image
        return body

    async def start(self, owner):
        async with self.lock(owner):
            if self.store.get(owner):
                return {"phase": "connected"}
            if owner in self.pending:
                return self._status(owner)
            if len(self.pending) >= MAX_PENDING:
                raise ValueError("too many pending logins; try again later")
            client = self.client_factory("")
            try:
                await client.connect()
                qr = await client.qr_login()
                output = io.BytesIO()
                qrcode.make(qr.url).save(output, format="PNG")
                login = Login(
                    client,
                    "data:image/png;base64," + base64.b64encode(output.getvalue()).decode(),
                    time.monotonic() + LOGIN_TTL,
                )
                self.pending[owner] = login
                login.task = asyncio.create_task(self._wait(owner, login, qr))
                return self._status(owner)
            except BaseException:
                await client.disconnect()
                raise

    async def _wait(self, owner, login, qr):
        try:
            await qr.wait(timeout=LOGIN_TTL)
            async with self.lock(owner):
                await self._save(owner, login)
        except errors.SessionPasswordNeededError:
            login.phase = "password_needed"
            login.image = ""
        except asyncio.CancelledError:
            raise
        except (TimeoutError, errors.RPCError, OSError, ValueError):
            login.phase = "expired"
            login.image = ""
            await login.client.disconnect()

    async def _save(self, owner, login):
        if self.pending.get(owner) is not login:
            return
        if not await login.client.is_user_authorized():
            raise ValueError("Telegram authorization incomplete")
        self.store.put(owner, login.client.session.save())
        self.pending.pop(owner)
        await login.client.disconnect()

    async def password(self, owner, password):
        async with self.lock(owner):
            login = self.pending.get(owner)
            if not login or login.phase != "password_needed" or time.monotonic() >= login.expires:
                raise ValueError("login expired; disconnect and start again")
            try:
                await login.client.sign_in(password=password)
            except errors.PasswordHashInvalidError:
                raise ValueError("incorrect Telegram password") from None
            await self._save(owner, login)
            return {"phase": "connected"}

    async def disconnect(self, owner):
        async with self.lock(owner):
            login = self.pending.pop(owner, None)
            if login:
                if login.task:
                    login.task.cancel()
                    await asyncio.gather(login.task, return_exceptions=True)
                await login.client.disconnect()
            session = self.store.get(owner)
            # Remove local access even when Telegram is unavailable.
            self.store.delete(owner)
            revoked = True
            if session:
                client = self.client_factory(session)
                try:
                    await client.connect()
                    revoked = bool(await client.log_out())
                except (errors.RPCError, OSError):
                    revoked = False
                finally:
                    await client.disconnect()
            return {"phase": "disconnected", "telegram_session_revoked": revoked}

    @asynccontextmanager
    async def client(self, owner):
        async with self.lock(owner):
            session = self.store.get(owner)
            if not session:
                raise ValueError("Connect Telegram from your private Console connection page first")
            client = self.client_factory(session)
            try:
                await client.connect()
                if not await client.is_user_authorized():
                    self.store.delete(owner)
                    raise ValueError(
                        "Telegram disconnected; reconnect from your private connection page"
                    )
                async with asyncio.timeout(40):
                    yield client
            finally:
                await client.disconnect()

    async def close(self):
        for login in self.pending.values():
            if login.task:
                login.task.cancel()
        await asyncio.gather(
            *(x.task for x in self.pending.values() if x.task), return_exceptions=True
        )
        for login in self.pending.values():
            await login.client.disconnect()
        self.store.close()

    async def expire_logins(self):
        while True:
            await asyncio.sleep(15)
            for owner, login in list(self.pending.items()):
                if time.monotonic() < login.expires:
                    continue
                async with self.lock(owner):
                    if self.pending.get(owner) is not login:
                        continue
                    self.pending.pop(owner)
                    if login.task:
                        login.task.cancel()
                        await asyncio.gather(login.task, return_exceptions=True)
                    await login.client.disconnect()


class ConsoleOnly:
    """Pure ASGI middleware: authenticate before parsing any login or MCP body."""

    def __init__(self, app, token):
        if len(token) < 32:
            raise ValueError("service token must contain at least 32 characters")
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        supplied = headers.get(b"authorization", b"")
        try:
            validate_owner(headers.get(b"x-centaur-telegram-owner", b"").decode())
            authenticated = hmac.compare_digest(supplied, ("Bearer " + self.token).encode())
        except (ValueError, UnicodeError):
            authenticated = False
        if not authenticated:
            return await JSONResponse({"error": "unauthorized"}, status_code=401)(
                scope, receive, send
            )
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY:
                return await JSONResponse({"error": "request too large"}, status_code=413)(
                    scope, receive, send
                )
            if not message.get("more_body"):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, bounded_receive, send)


def create_app(accounts, token):
    # This is an internal service. Console is its only HTTP client and enforces
    # authentication; the Kubernetes policy limits ingress to Console pods.
    mcp = FastMCP(
        "Personal Telegram",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=os.environ.get(
                "TELEGRAM_ALLOWED_HOSTS", "centaur-telegram:8000,localhost:*,127.0.0.1:*"
            ).split(",")
        ),
    )

    def owner(ctx: Context):
        return validate_owner(ctx.request_context.request.headers["x-centaur-telegram-owner"])

    @mcp.tool(annotations={"readOnlyHint": True})
    async def search_dialogs(query: str, ctx: Context, limit: int = 20) -> list[dict]:
        """Find this user's Telegram conversations. Never adds them to shared search."""
        if not 1 <= limit <= 50 or not 1 <= len(query) <= 200:
            raise ValueError("Use a 1–200 character query and a limit from 1 to 50")
        async with accounts.client(owner(ctx)) as client:
            result = []
            async for dialog in client.iter_dialogs(limit=1000):
                if query.casefold() in (dialog.name or "").casefold():
                    result.append(
                        {"id": str(dialog.id), "name": dialog.name, "is_group": dialog.is_group}
                    )
                    if len(result) == limit:
                        break
            return result

    @mcp.tool(annotations={"readOnlyHint": True})
    async def get_messages(chat_id: str, ctx: Context, limit: int = 20) -> list[dict]:
        """Read recent messages from a conversation in this user's Telegram account."""
        if not 1 <= limit <= 50 or len(chat_id) > 100:
            raise ValueError("Use a conversation ID and a limit from 1 to 50")
        async with accounts.client(owner(ctx)) as client:
            # StringSession deliberately persists no conversation/message cache.
            # Resolve numeric IDs through this account's own accessible dialogs.
            entity = None
            async for dialog in client.iter_dialogs(limit=1000):
                if str(dialog.id) == chat_id:
                    entity = dialog.input_entity
                    break
            if entity is None:
                raise ValueError("Conversation not found in your first 1000 dialogs")
            return [serialize_message(x) async for x in client.iter_messages(entity, limit=limit)]

    @mcp.tool(annotations={"readOnlyHint": True})
    async def search_messages(query: str, ctx: Context, limit: int = 20) -> list[dict]:
        """Search messages in this user's Telegram account, only for their Archie DM."""
        if not 1 <= limit <= 50 or not 1 <= len(query) <= 200:
            raise ValueError("Use a 1–200 character query and a limit from 1 to 50")
        async with accounts.client(owner(ctx)) as client:
            return [
                serialize_message(x)
                async for x in client.iter_messages(None, search=query, limit=limit)
            ]

    async def connection(request: Request):
        who = validate_owner(request.headers["x-centaur-telegram-owner"])
        try:
            if request.method == "GET":
                result = await accounts.status(who)
            elif request.method == "DELETE":
                result = await accounts.disconnect(who)
            else:
                body = await request.json()
                if body.get("action") == "start":
                    result = await accounts.start(who)
                elif (
                    body.get("action") == "password"
                    and isinstance(body.get("password"), str)
                    and len(body["password"]) <= 1024
                ):
                    result = await accounts.password(who, body["password"])
                else:
                    raise ValueError("invalid connection action")
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except (ValueError, json.JSONDecodeError):
            return JSONResponse(
                {"error": "Connection failed or expired. Disconnect and try again."},
                status_code=400,
            )
        except (errors.RPCError, OSError):
            return JSONResponse(
                {"error": "Telegram is unavailable. Try again later."}, status_code=502
            )

    @asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            janitor = asyncio.create_task(accounts.expire_logins())
            try:
                yield
            finally:
                janitor.cancel()
                await asyncio.gather(janitor, return_exceptions=True)
                await accounts.close()

    app = Starlette(
        routes=[
            Route("/connection", connection, methods=["GET", "POST", "DELETE"]),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        lifespan=lifespan,
    )
    return ConsoleOnly(app, token)


def serialize_message(message):
    return {
        "id": message.id,
        "chat_id": str(utils.get_peer_id(message.peer_id)),
        "date": message.date.isoformat(),
        "text": (message.message or "")[:16000],
    }


def app_factory():
    store = SessionStore(
        Path(os.environ["TELEGRAM_STATE_PATH"]), os.environ["TELEGRAM_SESSION_KEY"]
    )
    api_id, api_hash = int(os.environ["TELEGRAM_API_ID"]), os.environ["TELEGRAM_API_HASH"]
    accounts = TelegramAccounts(
        store, lambda session: TelegramClient(StringSession(session), api_id, api_hash)
    )
    return create_app(accounts, os.environ["TELEGRAM_SERVICE_TOKEN"])
