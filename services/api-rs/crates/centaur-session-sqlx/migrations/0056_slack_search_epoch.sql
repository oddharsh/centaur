-- Runtime-owned freshness marker. Never accept this from ingress metadata.
ALTER TABLE sessions ADD COLUMN slack_search_epoch text;
