namespace FantasyCritic.Web.Helpers;
public class LeagueUserRelationship
{
    public LeagueUserRelationship(bool inOrInvitedToLeague, bool leagueManager)
    {
        InOrInvitedToLeague = inOrInvitedToLeague;
        LeagueManager = leagueManager;
    }

    public bool InOrInvitedToLeague { get; }
    public bool LeagueManager { get; }
}

public class LeagueYearUserRelationship
{
    public LeagueYearUserRelationship(bool inOrInvitedToLeague, bool activeInYear, bool leagueManager)
    {
        InOrInvitedToLeague = inOrInvitedToLeague;
        ActiveInYear = activeInYear;
        LeagueManager = leagueManager;
    }

    public bool InOrInvitedToLeague { get; }
    public bool ActiveInYear { get; }
    public bool LeagueManager { get; }
}

public class PublisherUserRelationship
{
    public PublisherUserRelationship(LeagueYearUserRelationship leagueYearRelationship, bool isPublisher)
    {
        InOrInvitedToLeague = leagueYearRelationship.InOrInvitedToLeague;
        ActiveInYear = leagueYearRelationship.ActiveInYear;
        LeagueManager = leagueYearRelationship.LeagueManager;
        IsPublisher = isPublisher;
    }

    public bool InOrInvitedToLeague { get; }
    public bool ActiveInYear { get; }
    public bool LeagueManager { get; }
    public bool IsPublisher { get; }
}

public class RequiredRelationship
{
    public static RequiredRelationship AllowAnonymous => new RequiredRelationship(false, false, false, false, false, true);
    public static RequiredRelationship LoggedIn => new RequiredRelationship(true, false, false, false, false, true);
    public static RequiredRelationship LeagueManager => new RequiredRelationship(true, true, true, true, false, false);

    private RequiredRelationship(bool mustBeLoggedIn, bool mustBeInOrInvitedToLeague, bool mustBeActiveInYear, bool mustBeLeagueManager, bool mustBePublisher, bool allowIfAdmin)
    {
        MustBeLoggedIn = mustBeLoggedIn;
        MustBeInOrInvitedToLeague = mustBeInOrInvitedToLeague;
        MustBeActiveInYear = mustBeActiveInYear;
        MustBeLeagueManager = mustBeLeagueManager;
        MustBePublisher = mustBePublisher;
        AllowIfAdmin = allowIfAdmin;
    }

    public bool MustBeLoggedIn { get; }
    public bool MustBeInOrInvitedToLeague { get; }
    public bool MustBeActiveInYear { get; }
    public bool MustBeLeagueManager { get; }
    public bool MustBePublisher { get; }
    public bool AllowIfAdmin { get; }
};
