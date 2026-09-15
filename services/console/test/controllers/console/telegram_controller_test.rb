require "test_helper"

class Console::TelegramControllerTest < ActionDispatch::IntegrationTest
  test "connection page requires login and a verified Slack identity" do
    get console_telegram_url
    assert_redirected_to login_path
    post login_url, params: { email: users(:member_user).email, password: "password123456" }
    get console_telegram_url
    assert_response :forbidden
  end

  test "connection actions always use the signed-in owner" do
    user = users(:member_user)
    UserIdentity.create!(user: user, provider: "slack", subject: "U0123456789", team_id: "T0123456789")
    post login_url, params: { email: user.email, password: "password123456" }
    owners = []
    gateway = Object.new
    gateway.define_singleton_method(:request) do |owner, **args|
      owners << owner.oid
      HttpClient::Response.new(status: 200, body: '{"phase":"connected","telegram_session_revoked":true}')
    end
    TelegramGateway.stub(:new, gateway) do
      get console_telegram_url, params: { owner: users(:acme_admin).oid }
      assert_response :ok
      assert_equal "no-store", response.headers["Cache-Control"]
      assert_includes response.body, "Connected"
      post console_telegram_url, params: { owner: users(:acme_admin).oid }
      assert_redirected_to console_telegram_path
      delete console_telegram_url, params: { owner: users(:acme_admin).oid }
      assert_redirected_to console_telegram_path
    end
    assert_equal [ user.oid ] * 3, owners
  end
end
