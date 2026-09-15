require "test_helper"

class Api::V1::SandboxTelegramControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = users(:member_user)
    @identity = UserIdentity.create!(user: @user, provider: "slack", subject: "U0123456789", team_id: "T0123456789")
    @principal = Principal.create!(foreign_id: "slack-user-t0123456789-u0123456789", kind: "slack_dm", created_by: users(:acme_admin), slack_user_id: "U0123456789", slack_team_id: "T0123456789")
    @proxy = proxies(:acme_proxy)
    @proxy.update!(principal: @principal)
    @body = { jsonrpc: "2.0", id: 1, method: "tools/list" }
  end

  test "only the primary DM owner is forwarded and caller owner fields are ignored" do
    seen = []
    gateway = Object.new
    gateway.define_singleton_method(:request) do |owner, **args|
      seen << [ owner.oid, args ]
      HttpClient::Response.new(status: 200, body: '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')
    end
    TelegramGateway.stub(:new, gateway) do
      call_mcp(@body.merge(owner: users(:acme_admin).oid))
    end
    assert_response :ok
    assert_equal @user.oid, seen.sole.first
    assert_equal "no-store", response.headers["Cache-Control"]
  end

  test "shared channel cannot use a personal requester connection" do
    @proxy.update!(principal: principals(:acme_channel), requester_principal: @principal)
    call_mcp
    assert_response :forbidden
  end

  test "group DMs and unqualified user principals cannot use personal Telegram" do
    assign_principal("slack-channel-g0123456789", kind: "slack_channel")
    call_mcp
    assert_response :forbidden
    assign_principal("slack-user-u0123456789", kind: "user")
    call_mcp
    assert_response :forbidden
  end

  test "another user or workspace cannot reuse a connection" do
    assign_principal("slack-user-t0123456789-u9999999999", subject: "U9999999999")
    call_mcp
    assert_response :forbidden
    assign_principal("slack-user-t9999999999-u0123456789", team: "T9999999999")
    call_mcp
    assert_response :forbidden
  end

  test "disabled users and removed Slack identities immediately lose access" do
    @user.update!(status: "disabled")
    call_mcp
    assert_response :forbidden
    @user.update!(status: "active")
    @identity.destroy!
    call_mcp
    assert_response :forbidden
  end

  test "stale proxy assignments and unauthenticated calls fail before Telegram" do
    with_env("CENTAUR_JWT_SIGNING_SECRET" => "test-secret") do
      token = SandboxEntitlements::Jwt.encode_for_proxy(@proxy)
      @proxy.update!(principal: principals(:acme_channel))
      post "/api/v1/sandbox/telegram/mcp", params: @body.to_json, headers: { "Authorization" => "Bearer #{token}", "Content-Type" => "application/json" }
    end
    assert_response :unauthorized
    post "/api/v1/sandbox/telegram/mcp", params: @body.to_json
    assert_response :unauthorized
  end

  private

  def assign_principal(foreign_id, kind: "slack_dm", subject: "U0123456789", team: "T0123456789")
    principal = Principal.create!(foreign_id: foreign_id, kind: kind, slack_user_id: subject, slack_team_id: team, created_by: users(:acme_admin))
    @proxy.update!(principal: principal)
  end

  def call_mcp(body = @body)
    with_env("CENTAUR_JWT_SIGNING_SECRET" => "test-secret") do
      token = SandboxEntitlements::Jwt.encode_for_proxy(@proxy)
      post "/api/v1/sandbox/telegram/mcp", params: body.to_json, headers: { "Authorization" => "Bearer #{token}", "Content-Type" => "application/json" }
    end
  end
end
