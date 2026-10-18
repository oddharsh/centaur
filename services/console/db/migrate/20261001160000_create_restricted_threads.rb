class CreateRestrictedThreads < ActiveRecord::Migration[8.1]
  def change
    create_table :restricted_threads do |t|
      t.string :thread_key, null: false
      t.string :source, null: false
      t.references :principal, foreign_key: { on_delete: :nullify }

      t.timestamps
    end

    add_index :restricted_threads, :thread_key, unique: true

    # The config hash a proxy last reported on /proxy/sync. iron-proxy reports
    # a hash only after it applied that config, so this is the proxy's ack.
    add_column :proxies, :reported_config_hash, :string
    add_column :proxies, :reported_config_hash_at, :datetime
  end
end
