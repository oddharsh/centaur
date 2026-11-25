require "openssl"

module PrincipalClaim
  # ES256 claims that tell a downstream service (Anima) which principal a
  # sandbox request runs as. iron-proxy injects them as X-Centaur-Principal on
  # the configured hosts only; the sandbox never holds the token or the key.
  #
  # Signed with its own P-256 key, never CENTAUR_JWT_SIGNING_SECRET: a holder of
  # that HS256 secret can forge tokens centaur-api accepts, so it must stay
  # inside Centaur. The verifier stores only the public JWK (`public_jwk`).
  module Jwt
    HEADER = "X-Centaur-Principal".freeze
    ISSUER = "centaur-console".freeze
    # Same rotation window and lifetime as ApiServer::Jwt, so the snapshot
    # staleness check that rebuilds on a window boundary covers both tokens.
    # Anima rejects exp - iat > 7200.
    WINDOW_SECONDS = ApiServer::Jwt::DEFAULT_WINDOW_SECONDS
    TTL_SECONDS = ApiServer::Jwt::DEFAULT_TTL_SECONDS

    module_function

    def configured?
      private_key.present? && hosts.any?
    end

    # One proxy secret per host, because `aud` must equal the target host and a
    # secret carries a single value.
    def proxy_secrets_for(principal, now: Time.current)
      return [] unless configured?
      return [] if principal.foreign_id.blank?

      hosts.map do |host|
        {
          "source" => { "type" => "control_plane", "value" => encode(principal, audience: host, now: now) },
          "inject" => { "header" => HEADER, "formatter" => "{{ .Value }}" },
          "rules" => [ { "host" => host } ]
        }
      end
    end

    def encode(principal, audience:, now: Time.current)
      issued_at = CentaurJwt::WindowedToken.window_start(principal.oid, now.to_i, window_seconds: WINDOW_SECONDS)
      payload = {
        "iss" => ISSUER,
        "aud" => audience,
        "sub" => principal.foreign_id,
        "iat" => issued_at,
        "exp" => issued_at + TTL_SECONDS
      }
      ::JWT.encode(payload, private_key, "ES256", { kid: kid })
    end

    def public_jwk
      key = private_key
      raise ArgumentError, "CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY is not set" if key.nil?

      ::JWT::JWK.new(key, { kid: kid, alg: "ES256", use: "sig" }).export
    end

    # RFC 7638 thumbprint, derived from the key so the kid cannot drift from it.
    def kid
      ::JWT::JWK::Thumbprint.new(::JWT::JWK.new(private_key)).to_s
    end

    def hosts
      Principal.normalize_hosts(ENV["CENTAUR_PRINCIPAL_CLAIM_HOSTS"].to_s.split(","))
    end

    def private_key
      pem = ENV["CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY"].to_s
      return nil if pem.blank?

      key = OpenSSL::PKey::EC.new(pem)
      raise ArgumentError, "CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY must be a P-256 key" unless key.group.curve_name == "prime256v1"
      raise ArgumentError, "CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY must be a private key" unless key.private?

      key
    end
  end
end
