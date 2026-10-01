# A conversation thread that has read restricted data (today: personal
# Telegram). Every proxy assigned to the thread from then on serves only the
# operator's restricted egress rules (see RestrictedEgress). There is no
# expiry: the harness keeps the thread's transcript, so the data stays in the
# agent's context for every later turn, including after a sandbox is recycled.
class RestrictedThread < ApplicationRecord
  oid_prefix "rth"

  SOURCES = %w[personal_telegram].freeze

  belongs_to :principal, optional: true

  # Uniqueness is the database index's job: a model-level check would fail an
  # already-latched thread's next read before create_or_find_by! can fall back
  # to the existing row.
  validates :thread_key, presence: true
  validates :source, inclusion: { in: SOURCES }
end
