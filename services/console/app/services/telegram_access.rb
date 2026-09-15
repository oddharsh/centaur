# Console is the sole authorization boundary for the private Telegram service.
# Requester credentials never override a shared conversation's primary principal.
class TelegramAccess
  def self.identity_for(user)
    return nil unless user&.active?

    UserIdentity.unambiguous_slack_identity(UserIdentity.slack.where(user_id: user.id))
  end

  def self.owner_for_principal(principal)
    return nil unless principal&.kind == "slack_dm"

    match = /\Aslack-user-(t[a-z0-9]+)-(u[a-z0-9]+)\z/.match(principal.foreign_id.to_s)
    return nil unless match

    team, subject = match.captures.map(&:upcase)
    return nil unless principal.slack_team_id == team && principal.slack_user_id == subject

    identity = UserIdentity.slack.find_by(subject: subject, team_id: team)
    user = identity&.user
    user if identity_for(user) == [ subject, team ]
  end
end
