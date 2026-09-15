module Api
  module V1
    module Sandbox
      class TelegramController < Api::SandboxBaseController
        def create
          # Authenticate against the current primary principal on EVERY request.
          # Never use caller-supplied owner IDs, requester grants, or email matches.
          owner = TelegramAccess.owner_for_principal(current_proxy.principal)
          return render_error(status: :forbidden, message: "Personal Telegram is available only in your own Slack DM") unless owner
          return head :payload_too_large if request.raw_post.bytesize > 65_536

          body = JSON.parse(request.raw_post)
          return head :bad_request unless body.is_a?(Hash) && body["jsonrpc"] == "2.0"

          result = TelegramGateway.new.request(owner, method: :post, path: "/mcp", body: body)
          response.headers["Cache-Control"] = "no-store"
          render body: result.body, status: result.status, content_type: "application/json"
        rescue JSON::ParserError
          head :bad_request
        rescue TelegramGateway::Unavailable
          render_error(status: :service_unavailable, message: "Personal Telegram is unavailable")
        end
      end
    end
  end
end
