class TelegramGateway
  class Unavailable < StandardError; end

  def self.configured?
    ConsoleEnv["TELEGRAM_SERVICE_URL"].present? && ConsoleEnv["TELEGRAM_SERVICE_TOKEN"].present?
  end

  def initialize
    raise Unavailable unless self.class.configured?
    @url = ConsoleEnv["TELEGRAM_SERVICE_URL"].delete_suffix("/")
    # MCP returns both structured content and an escaped text representation.
    # Allow the bounded 50 x 16k-character result without truncating valid JSON.
    @http = HttpClient.new(open_timeout: 5, read_timeout: 45, max_body_bytes: 16 * 1024 * 1024)
  end

  def request(user, method:, path:, body: nil)
    raise ArgumentError unless %i[get post delete].include?(method) && %w[/connection /mcp].include?(path)

    headers = {
      "Authorization" => "Bearer #{ConsoleEnv['TELEGRAM_SERVICE_TOKEN']}",
      "X-Centaur-Telegram-Owner" => user.oid,
      "Accept" => "application/json, text/event-stream",
      "MCP-Protocol-Version" => "2025-11-25"
    }
    result = @http.request(method: method, url: "#{@url}#{path}", json: body, headers: headers)
    result.json # Reject malformed or truncated provider responses.
    result
  rescue IOError, SystemCallError, Timeout::Error, JSON::ParserError
    raise Unavailable
  end
end
