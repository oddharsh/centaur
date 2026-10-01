require "test_helper"

class RestrictedEgressTest < ActiveSupport::TestCase
  RULES = [
    { "host" => "api.anthropic.com" },
    { "host" => "*.googleapis.com", "methods" => [ "GET" ] },
    { "cidr" => "10.0.0.0/8" }
  ].freeze
  THREAD = "slack:T0123456789:D0123456789:1700000000.000100".freeze

  setup do
    @proxy = proxies(:acme_proxy)
    @proxy.update!(labels: { RestrictedEgress::THREAD_KEY_LABEL => THREAD })
  end

  test "operator rules parse from the environment" do
    assert_equal RULES, RestrictedEgress.operator_rules(RestrictedEgress::RULES_ENV => RULES.to_json)
  end

  test "unset, empty, or malformed operator rules are not configured" do
    [
      nil,
      "",
      "not json",
      "{}",
      "[]",
      [ { "host" => "a.example", "cidr" => "10.0.0.0/8" } ].to_json,
      [ { "methods" => [ "GET" ] } ].to_json,
      [ { "host" => "a.example", "extra" => true } ].to_json,
      [ { "host" => "a.example", "paths" => "/x" } ].to_json,
      [ { "host" => "a.example", "methods" => [ "" ] } ].to_json
    ].each do |raw|
      env = raw.nil? ? {} : { RestrictedEgress::RULES_ENV => raw }
      refute RestrictedEgress.configured?(env), "accepted #{raw.inspect}"
    end
  end

  test "restricted rules always keep Console's sandbox routes reachable" do
    rules = RestrictedEgress.rules_for(sandbox_entitlements_hosts: [ "Console.Example." ],
                                       env: { RestrictedEgress::RULES_ENV => RULES.to_json })
    assert_equal RULES, rules.first(3)
    assert_equal({ "host" => "console.example", "methods" => RestrictedEgress::CONSOLE_METHODS,
                   "paths" => [ Proxy::SANDBOX_ENTITLEMENTS_PATH_PATTERN ] }, rules.last)
  end

  test "rules removed after a latch leave only Console reachable" do
    rules = RestrictedEgress.rules_for(sandbox_entitlements_hosts: [ "console.example" ], env: {})
    assert_equal [ "console.example" ], rules.map { |rule| rule["host"] }
  end

  test "a proxy is restricted only while its thread is latched" do
    refute RestrictedEgress.restricted?(@proxy)
    RestrictedThread.create!(thread_key: THREAD, source: "personal_telegram")
    assert RestrictedEgress.restricted?(@proxy)
    @proxy.update!(labels: { RestrictedEgress::THREAD_KEY_LABEL => "slack:T1:D1:2.0" })
    refute RestrictedEgress.restricted?(@proxy)
  end

  test "a latched thread's config carries the rules and a new hash" do
    with_rules do
      open_hash = @proxy.config_hash
      refute @proxy.sync_config_snapshot[:config].key?("rules")

      RestrictedThread.create!(thread_key: THREAD, source: "personal_telegram")
      snapshot = @proxy.sync_config_snapshot
      assert_equal RULES, snapshot[:config].fetch("rules").first(3)
      refute_equal open_hash, snapshot[:config_hash]
    end
  end

  test "latch refuses without operator rules or a thread label" do
    assert_raises(RestrictedEgress::NotConfigured) { RestrictedEgress.latch!(@proxy, source: "personal_telegram") }
    with_rules do
      @proxy.update!(labels: {})
      assert_raises(RestrictedEgress::NoThread) { RestrictedEgress.latch!(@proxy, source: "personal_telegram") }
    end
    assert_equal 0, RestrictedThread.count
  end

  test "latch records the thread and fails closed until the proxy reports the restricted config" do
    with_rules do
      @proxy.update_columns(reported_config_hash: @proxy.config_hash)
      assert_raises(RestrictedEgress::NotApplied) do
        RestrictedEgress.latch!(@proxy, source: "personal_telegram", timeout: 0, poll: 0)
      end
      thread = RestrictedThread.find_by!(thread_key: THREAD)
      assert_equal "personal_telegram", thread.source
      assert_equal @proxy.principal, thread.principal
    end
  end

  test "latch returns once the proxy reports the restricted config" do
    with_rules do
      RestrictedThread.create!(thread_key: THREAD, source: "personal_telegram")
      @proxy.update_columns(reported_config_hash: @proxy.reload.config_hash)
      assert_nil RestrictedEgress.latch!(@proxy, source: "personal_telegram", timeout: 0, poll: 0)
      assert_equal 1, RestrictedThread.count
    end
  end

  test "an ack from a proxy reassigned to another thread does not count" do
    with_rules do
      RestrictedThread.create!(thread_key: THREAD, source: "personal_telegram")
      other = @proxy.labels.merge(RestrictedEgress::THREAD_KEY_LABEL => "slack:T1:D1:2.0")
      @proxy.update_columns(labels: other)
      @proxy.update_columns(reported_config_hash: @proxy.reload.config_hash)
      assert_raises(RestrictedEgress::NotApplied) do
        RestrictedEgress.await_applied!(@proxy, timeout: 0, poll: 0)
      end
    end
  end

  test "the proxy records a reported hash only when it changes" do
    @proxy.record_reported_config_hash!("sha256:one")
    first_at = @proxy.reload.reported_config_hash_at
    @proxy.record_reported_config_hash!("sha256:one")
    assert_equal first_at, @proxy.reload.reported_config_hash_at
    @proxy.record_reported_config_hash!(nil)
    assert_equal "sha256:one", @proxy.reload.reported_config_hash
  end

  private

  def with_rules(&block)
    with_env(RestrictedEgress::RULES_ENV => RULES.to_json, &block)
  end
end
