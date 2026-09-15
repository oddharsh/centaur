class Console::TelegramController < ApplicationController
  layout "console"
  before_action :require_slack_identity
  before_action :private_response
  rescue_from TelegramGateway::Unavailable, with: :unavailable

  def show
    result = TelegramGateway.new.request(current_user, method: :get, path: "/connection")
    return unavailable unless result.success?
    @connection = result.json
  end

  def create
    result = TelegramGateway.new.request(current_user, method: :post, path: "/connection", body: { action: "start" })
    redirect_to console_telegram_path, alert: ("Telegram connection could not start." unless result.success?)
  end

  def update
    password = params[:password].to_s
    return head :bad_request if password.bytesize > 1024

    result = TelegramGateway.new.request(current_user, method: :post, path: "/connection", body: { action: "password", password: password })
    redirect_to console_telegram_path, alert: ("Telegram sign-in failed or expired. Try again." unless result.success?)
  end

  def destroy
    result = TelegramGateway.new.request(current_user, method: :delete, path: "/connection")
    return unavailable unless result.success?
    notice = result.json["telegram_session_revoked"] == false ? "Disconnected from Archie. Also revoke this session in Telegram Settings > Devices." : "Telegram disconnected."
    redirect_to console_telegram_path, notice: notice
  end

  private

  def require_slack_identity
    return if TelegramAccess.identity_for(current_user)
    render plain: "Sign in to Console with Slack before connecting Telegram.", status: :forbidden
  end

  def private_response
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
  end

  def unavailable
    render plain: "Telegram connection service is unavailable.", status: :service_unavailable
  end
end
