require "test_helper"

class PrincipalClaimJwtTest < ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  PROD_HOST = "warmhearted-oyster-325.convex.site".freeze
  STAGING_HOST = "wandering-goat-598.convex.site".freeze

  setup do
    @signing_key = OpenSSL::PKey::EC.generate("prime256v1")
    @alice = create_principal("slack-user-t03894zvc1e-u05urg20ycr")
    @bob = create_principal("slack-user-t03894zvc1e-u0bob000000")
  end

  test "injects a claim per principal that verifies against the public JWK" do
    with_claim_env(hosts: PROD_HOST) do
      public_jwk = PrincipalClaim::Jwt.public_jwk

      [ @alice, @bob ].each do |principal|
        entry = claim_entries(principal).sole
        assert_equal [ { "host" => PROD_HOST } ], entry.fetch("rules")
        assert_equal "{{ .Value }}", entry.dig("inject", "formatter")

        claims, header = verify(entry.dig("source", "value"), public_jwk, aud: PROD_HOST)
        assert_equal principal.foreign_id, claims.fetch("sub")
        assert_equal PROD_HOST, claims.fetch("aud")
        assert_equal "centaur-console", claims.fetch("iss")
        assert_equal 3600, claims.fetch("exp") - claims.fetch("iat")
        assert_equal "ES256", header.fetch("alg")
        assert_equal public_jwk.fetch(:kid), header.fetch("kid")
      end
    end
  end

  test "each host gets a claim whose aud is that host only" do
    with_claim_env(hosts: "#{PROD_HOST},#{STAGING_HOST}") do
      public_jwk = PrincipalClaim::Jwt.public_jwk
      entries = claim_entries(@alice)

      assert_equal [ [ { "host" => PROD_HOST } ], [ { "host" => STAGING_HOST } ] ], entries.map { |e| e.fetch("rules") }
      claims, _header = verify(entries.last.dig("source", "value"), public_jwk, aud: STAGING_HOST)
      assert_equal STAGING_HOST, claims.fetch("aud")
      assert_raises(JWT::InvalidAudError) { verify(entries.last.dig("source", "value"), public_jwk, aud: PROD_HOST) }
    end
  end

  test "a claim signed by another key fails verification" do
    other_jwk = JWT::JWK.new(OpenSSL::PKey::EC.generate("prime256v1"), { kid: "other", alg: "ES256" }).export
    with_claim_env(hosts: PROD_HOST) do
      token = claim_entries(@alice).sole.dig("source", "value")
      assert_raises(JWT::VerificationError) { verify(token, other_jwk, aud: PROD_HOST) }
    end
  end

  test "public JWK carries no private part" do
    with_claim_env(hosts: PROD_HOST) do
      jwk = PrincipalClaim::Jwt.public_jwk
      assert_equal %i[alg crv kid kty use x y], jwk.keys.sort
      assert_equal "P-256", jwk.fetch(:crv)
    end
  end

  test "no header without hosts, without a key, or without a foreign id" do
    with_claim_env(hosts: nil) { assert_empty claim_entries(@alice) }
    with_env("CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY" => nil, "CENTAUR_PRINCIPAL_CLAIM_HOSTS" => PROD_HOST) do
      assert_empty claim_entries(@alice)
    end
    with_claim_env(hosts: PROD_HOST) do
      assert_empty claim_entries(create_principal(nil))
      assert_equal 1, claim_entries(@alice).size
    end
  end

  test "a snapshot from before the claim window is stale even without the HS256 secret" do
    with_env("CENTAUR_JWT_SIGNING_SECRET" => nil) do
      with_claim_env(hosts: PROD_HOST) do
        window_start = ApiServer::Jwt.window_start_for(@alice, Time.current.to_i)
        travel_to Time.zone.at(window_start + 60)
        snapshot = PrincipalSyncConfigSnapshot.build_for(@alice)
        snapshot.update_columns(updated_at: Time.zone.at(window_start - 1))
        assert_not snapshot.fresh_for?(@alice)

        snapshot.update_columns(updated_at: Time.zone.at(window_start))
        assert snapshot.fresh_for?(@alice)
      end
    end
  end

  test "rejects a key on another curve" do
    with_env("CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY" => OpenSSL::PKey::EC.generate("secp384r1").to_pem,
             "CENTAUR_PRINCIPAL_CLAIM_HOSTS" => PROD_HOST) do
      assert_raises(ArgumentError) { PrincipalClaim::Jwt.public_jwk }
    end
  end

  private

  def create_principal(foreign_id)
    Principal.create!(foreign_id: foreign_id, kind: "user", created_by: users(:acme_admin))
  end

  def with_claim_env(hosts:, &block)
    with_env(
      "CENTAUR_PRINCIPAL_CLAIM_PRIVATE_KEY" => @signing_key.to_pem,
      "CENTAUR_PRINCIPAL_CLAIM_HOSTS" => hosts,
      &block
    )
  end

  def claim_entries(principal)
    PrincipalSyncConfigSnapshot.config_for(principal).fetch("secrets").select do |secret|
      secret.dig("inject", "header") == PrincipalClaim::Jwt::HEADER
    end
  end

  # Verifies the way Anima does: public JWK only, ES256 only, exact aud and iss.
  def verify(token, public_jwk, aud:)
    key = JWT::JWK.import(public_jwk).verify_key
    JWT.decode(token, key, true, algorithm: "ES256", aud: aud, iss: "centaur-console", verify_aud: true, verify_iss: true)
  end
end
