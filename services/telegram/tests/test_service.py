import asyncio
import datetime
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient
from telethon import errors
from telethon.tl.types import PeerUser

from service import TelegramAccounts, create_app
from store import SessionStore

TOKEN = "synthetic-service-token-for-local-tests-only"


class FakeClient:
    def __init__(self, session):
        self.value = session
        self.session = SimpleNamespace(save=lambda: "new-session")
        self.authorized = bool(session)
        self.closed = False
        self.revoked = False
        self.scanned = asyncio.Event()
        self.require_password = False

    async def connect(self):
        pass

    async def disconnect(self):
        self.closed = True

    async def is_user_authorized(self):
        return self.authorized

    async def qr_login(self):
        async def wait(timeout):
            await self.scanned.wait()
            if self.require_password:
                raise errors.SessionPasswordNeededError(None)
            self.authorized = True

        return SimpleNamespace(url="tg://login?token=synthetic", wait=wait)

    async def sign_in(self, password):
        if password != "synthetic-password":
            raise errors.PasswordHashInvalidError(None)
        self.authorized = True

    async def log_out(self):
        self.revoked = True
        return True


@pytest.fixture
def store(tmp_path):
    return SessionStore(tmp_path / "state.db", Fernet.generate_key().decode())


def test_encryption_and_owner_isolation(store, tmp_path):
    store.put("usr_A", "synthetic-private-session-A")
    store.put("usr_B", "synthetic-private-session-B")
    assert store.get("usr_A") == "synthetic-private-session-A"
    assert store.get("usr_C") is None
    for path in tmp_path.iterdir():
        assert b"synthetic-private-session" not in path.read_bytes()
    store.delete("usr_A")
    assert store.get("usr_A") is None
    assert store.get("usr_B") == "synthetic-private-session-B"
    with pytest.raises(ValueError):
        store.get("../../usr_B")
    store.close()


def test_ciphertext_cannot_be_reassigned_to_another_owner(store):
    store.put("usr_A", "synthetic-session-A")
    store.put("usr_B", "synthetic-session-B")
    store.db.execute(
        "UPDATE sessions SET value=(SELECT value FROM sessions WHERE owner='usr_A') WHERE owner='usr_B'"
    )
    with pytest.raises(ValueError, match="owner mismatch"):
        store.get("usr_B")
    store.close()


async def test_qr_login_is_bound_to_owner_and_saved_only_after_scan(store):
    clients = []

    def factory(session):
        client = FakeClient(session)
        clients.append(client)
        return client

    accounts = TelegramAccounts(store, factory)
    assert (await accounts.start("usr_A"))["phase"] == "waiting"
    assert store.get("usr_A") is None
    assert await accounts.status("usr_B") == {"phase": "disconnected"}
    clients[0].scanned.set()
    await accounts.pending["usr_A"].task
    assert await accounts.status("usr_A") == {"phase": "connected"}
    assert clients[0].closed
    await accounts.close()


async def test_two_factor_and_disconnect_revoke_only_owner(store):
    clients = []

    def factory(session):
        client = FakeClient(session)
        clients.append(client)
        return client

    accounts = TelegramAccounts(store, factory)
    await accounts.start("usr_A")
    clients[0].require_password = True
    clients[0].scanned.set()
    await accounts.pending["usr_A"].task
    assert (await accounts.status("usr_A"))["phase"] == "password_needed"
    with pytest.raises(ValueError):
        await accounts.password("usr_B", "synthetic-password")
    with pytest.raises(ValueError):
        await accounts.password("usr_A", "incorrect")
    assert store.get("usr_A") is None
    await accounts.password("usr_A", "synthetic-password")
    store.put("usr_B", "synthetic-session-B")
    await accounts.disconnect("usr_A")
    assert clients[-1].revoked
    assert store.get("usr_B") == "synthetic-session-B"
    with pytest.raises(ValueError):
        async with accounts.client("usr_A"):
            pytest.fail("disconnected owner received a client")
    await accounts.close()


async def test_expired_or_cancelled_login_cannot_restore_access(store):
    accounts = TelegramAccounts(store, FakeClient)
    await accounts.start("usr_A")
    login = accounts.pending["usr_A"]
    await accounts.disconnect("usr_A")
    login.client.scanned.set()
    await asyncio.sleep(0)
    assert store.get("usr_A") is None
    assert login.client.closed
    await accounts.close()


class CanaryAccounts:
    def __init__(self):
        self.seen = []
        self.connected = {"usr_A", "usr_B"}

    @asynccontextmanager
    async def client(self, owner):
        self.seen.append(owner)
        if owner not in self.connected:
            raise ValueError("disconnected")

        async def messages(*args, **kwargs):
            yield SimpleNamespace(
                id=1,
                peer_id=PeerUser(123),
                date=datetime.datetime.now(datetime.UTC),
                message=f"CANARY-{owner}",
            )

        yield SimpleNamespace(iter_messages=messages)

    async def close(self):
        pass

    async def expire_logins(self):
        await asyncio.Event().wait()


def headers(owner="usr_A", token=TOKEN):
    return {
        "Authorization": "Bearer " + token,
        "X-Centaur-Telegram-Owner": owner,
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
    }


def test_mcp_cross_user_canaries_and_no_auth_bypass():
    accounts = CanaryAccounts()
    with TestClient(create_app(accounts, TOKEN), base_url="http://localhost:8000") as client:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search_messages",
                "arguments": {"query": "CANARY", "owner": "usr_B"},
            },
        }
        assert client.post("/mcp", json=body).status_code == 401
        assert client.post("/mcp", json=body, headers=headers(token="wrong")).status_code == 401
        assert (
            client.post(
                "/mcp", json=body, headers={**headers(), "Authorization": b"Bearer \xff"}
            ).status_code
            == 401
        )
        assert accounts.seen == []
        assert client.post("/mcp", content=b"x" * 65537, headers=headers()).status_code == 413
        assert accounts.seen == []
        for owner in ["usr_A", "usr_B"]:
            result = client.post("/mcp", json=body, headers=headers(owner))
            assert result.status_code == 200
            assert "CANARY-" + owner in result.text
            other = "usr_B" if owner == "usr_A" else "usr_A"
            assert "CANARY-" + other not in result.text
        accounts.connected.remove("usr_A")
        assert client.post("/mcp", json=body, headers=headers()).json()["result"]["isError"]


def test_mcp_discovery_contains_only_read_tools_and_no_owner_argument():
    with TestClient(
        create_app(CanaryAccounts(), TOKEN), base_url="http://localhost:8000"
    ) as client:
        init = client.post(
            "/mcp",
            headers=headers(),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        )
        assert init.status_code == 200
        result = client.post(
            "/mcp", headers=headers(), json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        ).json()
        tools = result["result"]["tools"]
        assert {tool["name"] for tool in tools} == {
            "search_dialogs",
            "get_messages",
            "search_messages",
        }
        assert all(tool["annotations"]["readOnlyHint"] for tool in tools)
        assert all("owner" not in tool["inputSchema"]["properties"] for tool in tools)


async def test_failed_telegram_revocation_still_removes_local_access(store):
    class RefusingClient(FakeClient):
        async def log_out(self):
            return False

    store.put("usr_A", "synthetic-session-A")
    accounts = TelegramAccounts(store, RefusingClient)
    assert await accounts.disconnect("usr_A") == {
        "phase": "disconnected",
        "telegram_session_revoked": False,
    }
    assert store.get("usr_A") is None
    await accounts.close()
