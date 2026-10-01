require "test_helper"

class Api::V1::SandboxTelegramControllerTest < ActionDispatch::IntegrationTest
  THREAD = "slack:T0123456789:D0123456789:1700000000.000100".freeze
  RULES = [ { "host" => "api.anthropic.com" } ].to_json.freeze

  setup do
    @user = users(:member_user)
    @identity = UserIdentity.create!(user: @user, provider: "slack", subject: "U0123456789", team_id: "T0123456789")
    @principal = Principal.create!(foreign_id: "slack-user-t0123456789-u0123456789", kind: "slack_dm", created_by: users(:acme_admin), slack_user_id: "U0123456789", slack_team_id: "T0123456789")
    @proxy = proxies(:acme_proxy)
    @proxy.update!(principal: @principal, labels: { RestrictedEgress::THREAD_KEY_LABEL => THREAD })
    @body = { jsonrpc: "2.0", id: 1, method: "tools/list" }
  end

  test "only the primary DM owner is forwarded and caller owner fields are ignored" do
    seen = []
    with_restricted_egress(applied: true) do
      TelegramGateway.stub(:new, recording_gateway(seen)) do
        call_mcp(@body.merge(owner: users(:acme_admin).oid))
      end
    end
    assert_response :ok
    assert_equal @user.oid, seen.sole.first
    assert_equal "no-store", response.headers["Cache-Control"]
  end

  test "a read latches the thread before Telegram is called" do
    seen = []
    latched_before_call = nil
    gateway = Object.new
    gateway.define_singleton_method(:request) do |owner, **args|
      latched_before_call = RestrictedThread.exists?(thread_key: THREAD)
      seen << [ owner.oid, args ]
      HttpClient::Response.new(status: 200, body: "{}")
    end
    with_restricted_egress(applied: true) do
      TelegramGateway.stub(:new, gateway) { call_mcp }
    end
    assert_response :ok
    assert latched_before_call
    thread = RestrictedThread.find_by!(thread_key: THREAD)
    assert_equal "personal_telegram", thread.source
    assert_equal @principal, thread.principal
  end

  test "Telegram is refused when restricted egress is unconfigured, unbound, or unconfirmed" do
    seen = []
    TelegramGateway.stub(:new, recording_gateway(seen)) do
      call_mcp
      assert_response :service_unavailable

      with_restricted_egress(applied: false) { call_mcp }
      assert_response :service_unavailable

      @proxy.update!(labels: {})
      with_restricted_egress(applied: true) { call_mcp }
      assert_response :forbidden
    end
    assert_empty seen
  end

  test "shared channel cannot use a personal requester connection" do
    @proxy.update!(principal: principals(:acme_channel), requester_principal: @principal)
    with_restricted_egress(applied: true) { call_mcp }
    assert_response :forbidden
    assert_equal 0, RestrictedThread.count
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

  # The ack wait polls the proxy's reported hash; RestrictedEgressTest covers
  # it. Here it either succeeds at once or times out.
  def with_restricted_egress(applied:, &block)
    await = applied ? ->(*, **) { nil } : ->(*, **) { raise RestrictedEgress::NotApplied }
    with_env(RestrictedEgress::RULES_ENV => RULES) do
      RestrictedEgress.stub(:await_applied!, await, &block)
    end
  end

  def recording_gateway(seen)
    gateway = Object.new
    gateway.define_singleton_method(:request) do |owner, **args|
      seen << [ owner.oid, args ]
      HttpClient::Response.new(status: 200, body: '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')
    end
    gateway
  end

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
