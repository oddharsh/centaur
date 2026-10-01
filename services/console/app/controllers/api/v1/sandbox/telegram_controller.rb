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

          # Personal Telegram is restricted data: before any of it reaches the
          # sandbox, confine this thread's egress and wait for the proxy to
          # confirm. Every failure refuses the read.
          RestrictedEgress.latch!(current_proxy, source: "personal_telegram")

          result = TelegramGateway.new.request(owner, method: :post, path: "/mcp", body: body)
          response.headers["Cache-Control"] = "no-store"
          render body: result.body, status: result.status, content_type: "application/json"
        rescue JSON::ParserError
          head :bad_request
        rescue TelegramGateway::Unavailable
          render_error(status: :service_unavailable, message: "Personal Telegram is unavailable")
        rescue RestrictedEgress::NotConfigured
          render_error(status: :service_unavailable, message: "Personal Telegram needs restricted egress rules, which this deployment has not configured")
        rescue RestrictedEgress::NoThread
          render_error(status: :forbidden, message: "This thread can't use personal Telegram; start a new DM thread")
        rescue RestrictedEgress::NotApplied
          render_error(status: :service_unavailable, message: "Couldn't restrict this thread's network access in time; try again")
        end
      end
    end
  end
end
