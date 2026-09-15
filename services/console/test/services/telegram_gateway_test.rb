require "test_helper"

class TelegramGatewayTest < ActiveSupport::TestCase
  test "malformed provider responses become unavailable instead of partial MCP output" do
    transport = Object.new
    transport.define_singleton_method(:request) do |**_args|
      HttpClient::Response.new(status: 200, body: '{"result":')
    end
    with_env("CENTAUR_CONSOLE_TELEGRAM_SERVICE_URL" => "http://telegram:8000", "CENTAUR_CONSOLE_TELEGRAM_SERVICE_TOKEN" => "synthetic-test-token") do
      HttpClient.stub(:new, transport) do
        assert_raises(TelegramGateway::Unavailable) do
          TelegramGateway.new.request(users(:member_user), method: :post, path: "/mcp", body: {})
        end
      end
    end
  end
end
