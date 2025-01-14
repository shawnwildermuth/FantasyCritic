using FantasyCritic.Lib.Domain.Calculations;
using FantasyCritic.Lib.Domain.LeagueActions;
using FantasyCritic.Lib.Domain.Requests;
using FantasyCritic.Lib.Domain.Trades;
using FantasyCritic.Lib.Identity;

namespace FantasyCritic.Lib.Interfaces;

public interface IFantasyCriticRepo
{
    Task<League?> GetLeague(Guid id);
    Task<LeagueYear?> GetLeagueYear(League requestLeague, int requestYear);
    Task<LeagueYearKey?> GetLeagueYearKeyForPublisherID(Guid publisherID);
    Task CreateLeague(League league, int initialYear, LeagueOptions options);
    Task AddNewLeagueYear(League league, int year, LeagueOptions options);
    Task EditLeagueYear(LeagueYear leagueYear, IReadOnlyDictionary<Guid, int> slotAssignments, LeagueAction settingsChangeAction);

    Task<IReadOnlyList<FantasyCriticUser>> GetUsersInLeague(Guid leagueID);
    Task<IReadOnlyList<FantasyCriticUser>> GetActivePlayersForLeagueYear(League league, int year);
    Task SetPlayersActive(League league, int year, IReadOnlyList<FantasyCriticUser> mostRecentActivePlayers);
    Task SetPlayerActiveStatus(LeagueYear leagueYear, Dictionary<FantasyCriticUser, bool> usersToChange);
    Task<IReadOnlyList<FantasyCriticUser>> GetLeagueFollowers(League league);
    Task<IReadOnlyList<League>> GetLeaguesForUser(FantasyCriticUser user);
    Task<IReadOnlyList<LeagueYear>> GetLeagueYearsForUser(FantasyCriticUser user, int year);
    Task<IReadOnlyDictionary<FantasyCriticUser, IReadOnlyList<LeagueYearKey>>> GetUsersWithLeagueYearsWithPublisher();

    Task<IReadOnlyList<League>> GetFollowedLeagues(FantasyCriticUser user);
    Task FollowLeague(League league, FantasyCriticUser user);
    Task UnfollowLeague(League league, FantasyCriticUser user);

    Task<LeagueInvite?> GetInvite(Guid inviteID);
    Task<IReadOnlyList<LeagueInvite>> GetLeagueInvites(FantasyCriticUser currentUser);
    Task SetAutoDraft(Publisher publisher, bool autoDraft);
    Task<IReadOnlyList<LeagueInvite>> GetOutstandingInvitees(League league);
    Task SaveInvite(LeagueInvite leagueInvite);
    Task AcceptInvite(LeagueInvite leagueInvite, FantasyCriticUser user);
    Task DeleteInvite(LeagueInvite leagueInvite);
    Task AddPlayerToLeague(League league, FantasyCriticUser inviteUser);
    Task SaveInviteLink(LeagueInviteLink inviteLink);
    Task DeactivateInviteLink(LeagueInviteLink inviteID);
    Task<IReadOnlyList<LeagueInviteLink>> GetInviteLinks(League league);
    Task<LeagueInviteLink?> GetInviteLinkByInviteCode(Guid inviteCode);
    Task SetArchiveStatusForUser(League league, bool archive, FantasyCriticUser user);

    Task FullyRemovePublisher(LeagueYear leagueYear, Publisher deletePublisher);
    Task RemovePlayerFromLeague(League league, FantasyCriticUser removeUser);
    Task TransferLeagueManager(League league, FantasyCriticUser newManager);

    Task CreatePublisher(Publisher publisher);
    Task AddPublisherGame(PublisherGame publisherGame);
    Task AssociatePublisherGame(Publisher publisher, PublisherGame publisherGame, MasterGame masterGame);
    Task MergeMasterGame(MasterGame removeMasterGame, MasterGame mergeIntoMasterGame);
    Task ReorderPublisherGames(Publisher publisher, Dictionary<int, Guid?> slotStates);


    Task<IReadOnlyList<SupportedYear>> GetSupportedYears();
    Task<SupportedYear> GetSupportedYear(int year);

    Task<IReadOnlyList<LeagueYear>> GetLeagueYears(int year, bool includeDeleted = false);

    Task UpdatePublisherGameCalculatedStats(IReadOnlyDictionary<Guid, PublisherGameCalculatedStats> calculatedStats);
    Task UpdateLeagueWinners(IReadOnlyDictionary<LeagueYearKey, FantasyCriticUser> winningUsers);

    Task FullyRemovePublisherGame(LeagueYear leagueYear, Publisher publisher, PublisherGame publisherGame);

    Task<Result> ManagerRemovePublisherGame(LeagueYear leagueYear, Publisher publisher, PublisherGame publisherGame, FormerPublisherGame formerPublisherGame, LeagueAction leagueAction);
    Task ManuallyScoreGame(PublisherGame publisherGame, decimal? manualCriticScore);
    Task ManuallySetWillNotRelease(PublisherGame publisherGame, bool willNotRelease);

    Task CreatePickupBid(PickupBid currentBid);
    Task RemovePickupBid(PickupBid bid);
    Task<IReadOnlyList<PickupBid>> GetActivePickupBids(LeagueYear leagueYear, Publisher publisher);
    Task<IReadOnlyDictionary<LeagueYear, IReadOnlyList<PickupBid>>> GetActivePickupBids(int year, IReadOnlyList<LeagueYear> leagueYears);
    Task<IReadOnlyList<PickupBid>> GetActivePickupBids(LeagueYear leagueYear);
    Task<IReadOnlyList<PickupBid>> GetProcessedPickupBids(int year, IReadOnlyList<LeagueYear> allLeagueYears);
    Task<IReadOnlyList<PickupBid>> GetProcessedPickupBids(LeagueYear leagueYear);
    Task<PickupBid?> GetPickupBid(Guid bidID);
    Task SetBidPriorityOrder(IReadOnlyList<KeyValuePair<PickupBid, int>> bidPriorities);

    Task CreateDropRequest(DropRequest currentDropRequest);
    Task RemoveDropRequest(DropRequest dropRequest);
    Task<IReadOnlyList<DropRequest>> GetActiveDropRequests(LeagueYear leagueYear, Publisher publisher);
    Task<IReadOnlyDictionary<LeagueYear, IReadOnlyList<DropRequest>>> GetActiveDropRequests(int year, IReadOnlyList<LeagueYear> allLeagueYears);
    Task<IReadOnlyList<DropRequest>> GetProcessedDropRequests(LeagueYear leagueYear);
    Task<DropRequest?> GetDropRequest(Guid dropRequestID);

    Task<IReadOnlyList<QueuedGame>> GetQueuedGames(Publisher publisher);
    Task QueueGame(QueuedGame queuedGame);
    Task RemoveQueuedGame(QueuedGame queuedGame);
    Task SetQueueRankings(IReadOnlyList<KeyValuePair<QueuedGame, int>> queueRanks);

    Task AddLeagueAction(LeagueAction action);
    Task<IReadOnlyList<LeagueAction>> GetLeagueActions(LeagueYear leagueYear);
    Task ChangePublisherName(Publisher publisher, string publisherName);
    Task ChangePublisherIcon(Publisher publisher, string? publisherIcon);
    Task ChangeLeagueOptions(League league, string leagueName, bool publicLeague, bool testLeague);
    Task StartDraft(LeagueYear leagueYear);
    Task CompleteDraft(LeagueYear leagueYear);
    Task ResetDraft(LeagueYear leagueYear, Instant timestamp);

    Task SetDraftPause(LeagueYear leagueYear, bool pause);
    Task SetDraftOrder(IReadOnlyList<KeyValuePair<Publisher, int>> draftPositions);
    Task<IReadOnlyList<EligibilityOverride>> GetEligibilityOverrides(League league, int year);
    Task DeleteEligibilityOverride(LeagueYear leagueYear, MasterGame masterGame);
    Task SetEligibilityOverride(LeagueYear leagueYear, MasterGame masterGame, bool eligible);
    Task<IReadOnlyList<TagOverride>> GetTagOverrides(League league, int year);
    Task<IReadOnlyList<MasterGameTag>> GetTagOverridesForGame(League league, int year, MasterGame masterGame);
    Task SetTagOverride(LeagueYear leagueYear, MasterGame masterGame, IEnumerable<MasterGameTag> requestedTags);

    Task<SystemWideValues> GetSystemWideValues();
    Task<SystemWideSettings> GetSystemWideSettings();
    Task<SiteCounts> GetSiteCounts();
    Task SetActionProcessingMode(bool modeOn);

    Task EditPublisher(EditPublisherRequest editValues, LeagueAction leagueAction);
    Task DeletePublisher(Publisher publisher);
    Task DeleteLeagueYear(LeagueYear leagueYear);
    Task DeleteLeague(League league);
    Task DeleteLeagueActions(Publisher publisher);

    Task<IReadOnlyList<ActionProcessingSetMetadata>> GetActionProcessingSets();
    Task SaveProcessedActionResults(FinalizedActionProcessingResults actionProcessingResults);
    Task ManualMakePublisherGameSlotsConsistent(int year);
    Task UpdateSystemWideValues(SystemWideValues systemWideValues);
    Task PostNewManagerMessage(LeagueYear leagueYear, ManagerMessage domainMessage);
    Task<IReadOnlyList<ManagerMessage>> GetManagerMessages(LeagueYear leagueYear);
    Task<Result> DeleteManagerMessage(LeagueYear leagueYear, Guid messageID);
    Task<Result> DismissManagerMessage(Guid messageId, Guid userId);
    Task FinishYear(SupportedYear supportedYear);
    Task EditPickupBid(PickupBid bid, PublisherGame? conditionalDropPublisherGame, uint bidAmount);
    Task<FantasyCriticUser?> GetLeagueYearWinner(Guid leagueID, int year);
    Task CreateTrade(Trade trade);
    Task<IReadOnlyList<Trade>> GetTradesForLeague(LeagueYear leagueYear);
    Task<Trade?> GetTrade(Guid tradeID);
    Task EditTradeStatus(Trade trade, TradeStatus status, Instant? acceptedTimestamp, Instant? completedTimestamp);
    Task AddTradeVote(TradeVote tradeVote);
    Task DeleteTradeVote(Trade trade, FantasyCriticUser user);
    Task ExecuteTrade(ExecutedTrade executedTrade);

    async Task<League> GetLeagueOrThrow(Guid id)
    {
        var result = await GetLeague(id);
        if (result is null)
        {
            throw new Exception($"League not found: {id}");
        }

        return result;
    }

    async Task<LeagueYear> GetLeagueYearOrThrow(League league, int year)
    {
        var leagueYear = await GetLeagueYear(league, year);
        if (leagueYear is null)
        {
            throw new Exception($"League year not found: {league.LeagueID} | {year}");
        }

        return leagueYear;
    }
}
