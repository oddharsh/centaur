# Keeps restricted data from leaving a thread over the network.
#
# A proxy normally serves no allowlist, so a sandbox can reach any host. Once
# a thread reads restricted data, every proxy assigned to that thread serves
# top-level `rules`, which iron-proxy turns into a default-deny `allowlist`
# transform: only the operator's restricted egress rules plus Console's own
# sandbox routes stay reachable. Without this, a prompt injection in a web page
# read later in the same thread could carry the data out in a URL.
#
# The thread comes from the `centaur.thread_key` proxy label that api-rs sets
# on every assignment, so the latch follows the thread across sandbox
# recycles instead of dying with one proxy.
class RestrictedEgress
  RULES_ENV = "CENTAUR_RESTRICTED_EGRESS_RULES".freeze
  THREAD_KEY_LABEL = "centaur.thread_key".freeze
  RULE_KEYS = %w[host cidr methods paths].freeze
  CONSOLE_METHODS = %w[GET POST PUT PATCH DELETE].freeze
  # iron-proxy polls every 10s (+/-10%) and reports a hash on the poll after
  # it applied it, so an ack can take two intervals.
  APPLY_TIMEOUT = 30
  APPLY_POLL = 0.5

  class Error < StandardError; end
  # No operator rules: refuse restricted data rather than latch a thread
  # into a config that would cut off its model provider.
  class NotConfigured < Error; end
  # The proxy carries no thread label (a session that predates the label),
  # so there is nothing durable to latch.
  class NoThread < Error; end
  # The proxy did not confirm the restricted config in time.
  class NotApplied < Error; end

  # The operator's rules from CENTAUR_RESTRICTED_EGRESS_RULES: a JSON array of
  # iron-proxy rules, each with exactly one of `host` or `cidr` and optional
  # `methods` and `paths`. Nil when unset or malformed.
  def self.operator_rules(env = ENV)
    raw = env[RULES_ENV].to_s.strip
    return nil if raw.empty?

    rules = JSON.parse(raw)
    return nil unless rules.is_a?(Array) && rules.any? && rules.all? { |rule| valid_rule?(rule) }

    rules
  rescue JSON::ParserError
    nil
  end

  def self.configured?(env = ENV)
    !operator_rules(env).nil?
  end

  # The allowlist a restricted proxy serves. If the operator rules were removed
  # after a thread latched, only Console stays reachable: the thread fails
  # closed instead of reopening.
  def self.rules_for(sandbox_entitlements_hosts:, env: ENV)
    console = Principal.normalize_hosts(sandbox_entitlements_hosts).map do |host|
      { "host" => host, "methods" => CONSOLE_METHODS, "paths" => [ Proxy::SANDBOX_ENTITLEMENTS_PATH_PATTERN ] }
    end
    (operator_rules(env) || []) + console
  end

  def self.thread_key_for(proxy)
    labels = proxy.labels
    labels.is_a?(Hash) ? labels[THREAD_KEY_LABEL].presence : nil
  end

  def self.restricted?(proxy)
    key = thread_key_for(proxy)
    key.present? && RestrictedThread.exists?(thread_key: key)
  end

  # Latch the proxy's thread, then block until the proxy reports the
  # restricted config. Callers return restricted data only after this returns.
  def self.latch!(proxy, source:, timeout: APPLY_TIMEOUT, poll: APPLY_POLL)
    raise NotConfigured unless configured?

    key = thread_key_for(proxy)
    raise NoThread if key.blank?

    RestrictedThread.create_or_find_by!(thread_key: key) do |thread|
      thread.source = source
      thread.principal = proxy.principal
    end
    await_applied!(proxy, timeout: timeout, poll: poll)
  end

  def self.await_applied!(proxy, timeout:, poll:)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      proxy.reload
      # A proxy reassigned to an unlatched thread mid-wait would ack an open
      # config; that is not an ack of this latch.
      raise NotApplied unless restricted?(proxy)
      return if proxy.reported_config_hash.present? && proxy.reported_config_hash == proxy.config_hash
      raise NotApplied if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep poll
    end
  end

  def self.valid_rule?(rule)
    return false unless rule.is_a?(Hash) && rule.any? && (rule.keys - RULE_KEYS).empty?
    return false unless [ rule["host"], rule["cidr"] ].count { |v| v.is_a?(String) && v.strip.present? } == 1

    %w[methods paths].all? do |key|
      rule[key].nil? || (rule[key].is_a?(Array) && rule[key].all? { |v| v.is_a?(String) && v.strip.present? })
    end
  end
  private_class_method :valid_rule?
end
