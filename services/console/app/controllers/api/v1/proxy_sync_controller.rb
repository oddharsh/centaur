module Api
  module V1
    # POST /api/v1/proxy/sync
    #
    # iron-proxy polls this endpoint to fetch its config. It sends its current
    # config_hash; when that matches the freshly computed hash we return only the
    # hash (no payload), so the proxy skips re-applying. Otherwise we return the
    # full `secrets` and `transforms` payload.
    #
    # `secrets` populates the proxy's `secrets` transform. `transforms` carries
    # whole transforms the proxy splices into its pipeline: one gcp_auth,
    # gcp_id_token, hmac_sign, or aws_auth transform per granted secret, and one
    # bundled oauth_token transform. `postgres` carries one upstream-DSN
    # entry per granted PgDsnSecret, keyed by foreign_id; the proxy's
    # locally-defined listeners bind to these by foreign_id.
    #
    # Top-level `rules` (a default-deny allowlist) is sent only for a proxy
    # whose thread read restricted data; see RestrictedEgress. The `mcp` and
    # `ingest_token` fields the proxy also understands are intentionally
    # omitted: centaur-console has no models for them yet. Each secret still
    # carries its own per-secret `rules`.
    #
    # The config_hash a proxy sends is the one it last applied (iron-proxy
    # adopts a hash only after applying its config), so it is recorded as the
    # proxy's ack.
    class ProxySyncController < Api::ProxyBaseController
      def create
        current_proxy.record_reported_config_hash!(params[:config_hash].presence)
        snapshot = current_proxy.sync_config_snapshot
        current_hash = snapshot[:config_hash]

        if params[:config_hash].presence == current_hash
          render json: { config_hash: current_hash }
        else
          # The config is assembled from the proxy's principal (empty when
          # unassigned). status and principal_id let an unassigned proxy tell "no
          # config yet" apart from "config is genuinely empty", and detect a swap.
          config = snapshot[:config]
          body = {
            config_hash: current_hash,
            status: current_proxy.status,
            principal_id: current_proxy.principal&.oid,
            secrets: config["secrets"],
            transforms: config["transforms"],
            postgres: config["postgres"]
          }
          body[:rules] = config["rules"] if config.key?("rules")
          render json: body
        end
      end
    end
  end
end
