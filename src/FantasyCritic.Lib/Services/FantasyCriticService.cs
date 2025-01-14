using FantasyCritic.Lib.Domain.Calculations;
using FantasyCritic.Lib.Domain.LeagueActions;
using FantasyCritic.Lib.Domain.Requests;
using FantasyCritic.Lib.Domain.ScoringSystems;
using FantasyCritic.Lib.Domain.Trades;
using FantasyCritic.Lib.Extensions;
using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Interfaces;

namespace FantasyCritic.Lib.Services;

public class FantasyCriticService
{
    private readonly IFantasyCriticRepo _fantasyCriticRepo;
    private readonly IClock _clock;
    private readonly LeagueMemberService _leagueMemberService;
    private readonly InterLeagueService _interLeagueService;

    public FantasyCriticService(LeagueMemberService leagueMemberService, InterLeagueService interLeagueService,
        IFantasyCriticRepo fantasyCriticRepo, IClock clock)
    {
        _fantasyCriticRepo = fantasyCriticRepo;
        _clock = clock;
        _leagueMemberService = leagueMemberService;
        _interLeagueService = interLeagueService;
    }

    public Task<League?> GetLeagueByID(Guid id)
    {
        return _fantasyCriticRepo.GetLeague(id);
    }

    public async Task<LeagueYear?> GetLeagueYear(Guid id, int year)
    {
        var league = await GetLeagueByID(id);
        if (league is null)
        {
            return null;
        }

        var leagueYear = await _fantasyCriticRepo.GetLeagueYear(league, year);
        return leagueYear;
    }

    public Task<LeagueYearKey?> GetLeagueYearKeyForPublisherID(Guid publisherID)
    {
        return _fantasyCriticRepo.GetLeagueYearKeyForPublisherID(publisherID);
    }

    public async Task<Result<League>> CreateLeague(LeagueCreationParameters parameters)
    {
        LeagueOptions options = new LeagueOptions(parameters.LeagueYearParameters);

        var validateOptions = options.Validate();
        if (validateOptions.IsFailure)
        {
            return Result.Failure<League>(validateOptions.Error);
        }

        if (parameters.LeagueYearParameters.ScoringSystem.Name != DiminishingScoringSystem.StaticName)
        {
            return Result.Failure<League>("That scoring mode is no longer supported.");
        }

        IEnumerable<int> years = new List<int>() { parameters.LeagueYearParameters.Year };
        League newLeague = new League(Guid.NewGuid(), parameters.LeagueName, parameters.Manager, years, parameters.PublicLeague, parameters.TestLeague, false, 0);
        await _fantasyCriticRepo.CreateLeague(newLeague, parameters.LeagueYearParameters.Year, options);
        return Result.Success(newLeague);
    }

    public async Task<Result> EditLeague(LeagueYear leagueYear, LeagueYearParameters parameters)
    {
        if (leagueYear.SupportedYear.Finished)
        {
            return Result.Failure("You cannot edit a completed year.");
        }

        var league = leagueYear.League;
        LeagueOptions options = new LeagueOptions(parameters);
        var validateOptions = options.Validate();
        if (validateOptions.IsFailure)
        {
            return Result.Failure(validateOptions.Error);
        }

        if (parameters.ScoringSystem.Name != DiminishingScoringSystem.StaticName)
        {
            return Result.Failure("That scoring mode is no longer supported.");
        }

        IReadOnlyList<Publisher> publishers = leagueYear.Publishers;
        int maxStandardGames = publishers.Select(publisher => publisher.PublisherGames.Count(x => !x.CounterPick)).DefaultIfEmpty(0).Max();
        int maxCounterPicks = publishers.Select(publisher => publisher.PublisherGames.Count(x => x.CounterPick)).DefaultIfEmpty(0).Max();

        if (maxStandardGames > options.StandardGames)
        {
            return Result.Failure($"Cannot reduce number of standard games to {options.StandardGames} as a publisher has {maxStandardGames} standard games currently.");
        }
        if (maxCounterPicks > options.CounterPicks)
        {
            return Result.Failure($"Cannot reduce number of counter picks to {options.CounterPicks} as a publisher has {maxCounterPicks} counter picks currently.");
        }

        if (leagueYear.PlayStatus.DraftIsActive)
        {
            if (leagueYear.Options.GamesToDraft > parameters.GamesToDraft)
            {
                return Result.Failure("Cannot decrease the number of drafted games during the draft. Reset the draft if you need to do this.");
            }

            if (leagueYear.Options.CounterPicksToDraft > parameters.CounterPicksToDraft)
            {
                return Result.Failure("Cannot decrease the number of drafted counter picks during the draft. Reset the draft if you need to do this.");
            }
        }

        if (leagueYear.PlayStatus.DraftFinished)
        {
            if (leagueYear.Options.GamesToDraft != parameters.GamesToDraft)
            {
                return Result.Failure("Cannot change the number of drafted games after the draft.");
            }

            if (leagueYear.Options.CounterPicksToDraft != parameters.CounterPicksToDraft)
            {
                return Result.Failure("Cannot change the number of drafted counter picks after the draft.");
            }
        }

        int maxFreeGamesFreeDropped = publishers.Select(publisher => publisher.FreeGamesDropped).DefaultIfEmpty(0).Max();
        int maxWillNotReleaseGamesDropped = publishers.Select(publisher => publisher.WillNotReleaseGamesDropped).DefaultIfEmpty(0).Max();
        int maxWillReleaseGamesDropped = publishers.Select(publisher => publisher.WillReleaseGamesDropped).DefaultIfEmpty(0).Max();

        if (maxFreeGamesFreeDropped > options.FreeDroppableGames && options.FreeDroppableGames != -1)
        {
            return Result.Failure($"Cannot reduce number of unrestricted droppable games to {options.FreeDroppableGames} as a publisher has already dropped {maxFreeGamesFreeDropped} games.");
        }
        if (maxWillNotReleaseGamesDropped > options.WillNotReleaseDroppableGames && options.WillNotReleaseDroppableGames != -1)
        {
            return Result.Failure($"Cannot reduce number of 'will not release' droppable games to {options.WillNotReleaseDroppableGames} as a publisher has already dropped {maxWillNotReleaseGamesDropped} games.");
        }
        if (maxWillReleaseGamesDropped > options.WillReleaseDroppableGames && options.WillReleaseDroppableGames != -1)
        {
            return Result.Failure($"Cannot reduce number of 'will release' droppable games to {options.WillReleaseDroppableGames} as a publisher has already dropped {maxWillReleaseGamesDropped} games.");
        }

        var slotAssignments = GetNewSlotAssignments(parameters, leagueYear, publishers);
        var eligibilityOverrides = await GetEligibilityOverrides(league, parameters.Year);
        var tagOverrides = await GetTagOverrides(league, parameters.Year);
        var supportedYear = await _interLeagueService.GetSupportedYear(parameters.Year);

        LeagueYear newLeagueYear = new LeagueYear(league, supportedYear, options, leagueYear.PlayStatus, eligibilityOverrides,
            tagOverrides, leagueYear.DraftStartedTimestamp, leagueYear.WinningUser, publishers);

        var managerPublisher = leagueYear.GetManagerPublisherOrThrow();
        var differenceString = options.GetDifferenceString(leagueYear.Options);
        if (differenceString is not null)
        {
            LeagueAction settingsChangeAction = new LeagueAction(managerPublisher, _clock.GetCurrentInstant(), "League Year Settings Changed", differenceString, true);
            await _fantasyCriticRepo.EditLeagueYear(newLeagueYear, slotAssignments, settingsChangeAction);
        }

        return Result.Success();
    }

    private static IReadOnlyDictionary<Guid, int> GetNewSlotAssignments(LeagueYearParameters parameters, LeagueYear leagueYear, IReadOnlyList<Publisher> publishers)
    {
        var slotCountShift = parameters.StandardGames - leagueYear.Options.StandardGames;
        Dictionary<Guid, int> finalSlotAssignments = new Dictionary<Guid, int>();
        if (slotCountShift == 0)
        {
            return finalSlotAssignments;
        }

        foreach (var publisher in publishers)
        {
            Dictionary<Guid, int> slotAssignmentsForPublisher = new Dictionary<Guid, int>();
            var slots = publisher.GetPublisherSlots(leagueYear.Options);
            var filledNonCounterPickSlots = slots.Where(x => !x.CounterPick && x.PublisherGame is not null).ToList();

            int normalSlotNumber = 0;
            var normalSlots = filledNonCounterPickSlots.Where(x => x.SpecialGameSlot is null);
            foreach (var normalSlot in normalSlots)
            {
                slotAssignmentsForPublisher[normalSlot.PublisherGame!.PublisherGameID] = normalSlotNumber;
                normalSlotNumber++;
            }

            var specialSlots = filledNonCounterPickSlots.Where(x => x.SpecialGameSlot is not null);
            foreach (var specialSlot in specialSlots)
            {
                slotAssignmentsForPublisher[specialSlot.PublisherGame!.PublisherGameID] =
                    specialSlot.SlotNumber + slotCountShift;
            }

            bool invalidSlotsMade = slotAssignmentsForPublisher.GroupBy(x => x.Value).Any(x => x.Count() > 1);
            if (invalidSlotsMade)
            {
                //If we cannot do the more advance way to preserve slots, then just do the very basic thing, and line the games up.
                slotAssignmentsForPublisher = new Dictionary<Guid, int>();
                int allSlotNumber = 0;
                foreach (var slot in filledNonCounterPickSlots)
                {
                    slotAssignmentsForPublisher[slot.PublisherGame!.PublisherGameID] = allSlotNumber;
                    allSlotNumber++;
                }
            }

            foreach (var slot in slotAssignmentsForPublisher)
            {
                finalSlotAssignments[slot.Key] = slot.Value;
            }
        }

        return finalSlotAssignments;
    }

    public Task<IReadOnlyList<EligibilityOverride>> GetEligibilityOverrides(League league, int year)
    {
        return _fantasyCriticRepo.GetEligibilityOverrides(league, year);
    }

    public async Task AddNewLeagueYear(League league, int year, LeagueOptions options, LeagueYear mostRecentLeagueYear)
    {
        await _fantasyCriticRepo.AddNewLeagueYear(league, year, options);
        var mostRecentActivePlayers = await _fantasyCriticRepo.GetActivePlayersForLeagueYear(league, mostRecentLeagueYear.Year);
        await _fantasyCriticRepo.SetPlayersActive(league, year, mostRecentActivePlayers);
    }

    public async Task<YearCalculatedStatsSet> GetCalculatedStatsForYear(int year)
    {
        Dictionary<Guid, PublisherGameCalculatedStats> publisherGameCalculatedStats = new Dictionary<Guid, PublisherGameCalculatedStats>();
        IReadOnlyList<LeagueYear> leagueYears = await _fantasyCriticRepo.GetLeagueYears(year);
        IReadOnlyList<Publisher> allPublishersForYear = leagueYears.SelectMany(x => x.Publishers).ToList();
        var leagueYearDictionary = leagueYears.ToDictionary(x => x.Key);

        var currentDate = _clock.GetToday();
        Dictionary<LeagueYearKey, FantasyCriticUser> winningUsers = new Dictionary<LeagueYearKey, FantasyCriticUser>();
        var publishersByYear = allPublishersForYear.GroupBy(x => x.LeagueYearKey.Year);
        foreach (var publishersForYear in publishersByYear)
        {
            decimal highestPoints = 0m;
            foreach (var publisher in publishersForYear)
            {
                var leagueYear = leagueYearDictionary[publisher.LeagueYearKey];
                decimal totalPointsForPublisher = 0m;
                var slots = publisher.GetPublisherSlots(leagueYear.Options).Where(x => x.PublisherGame is not null).ToList();
                foreach (var publisherSlot in slots)
                {
                    //Before 2022, games that were 'ineligible' still gave points. It was just a warning.
                    var ineligiblePointsShouldCount = !SupportedYear.Year2022FeatureSupported(year);
                    var gameIsEligible = publisherSlot.SlotIsValid(leagueYear);
                    var pointsShouldCount = gameIsEligible || ineligiblePointsShouldCount;

                    decimal? fantasyPoints = publisherSlot.GetFantasyPoints(pointsShouldCount, leagueYear.Options.ScoringSystem, currentDate);
                    var stats = new PublisherGameCalculatedStats(fantasyPoints);
                    publisherGameCalculatedStats.Add(publisherSlot.PublisherGame!.PublisherGameID, stats);
                    if (fantasyPoints.HasValue)
                    {
                        totalPointsForPublisher += fantasyPoints.Value;
                    }
                }

                if (totalPointsForPublisher > highestPoints && leagueYear.WinningUser is null)
                {
                    highestPoints = totalPointsForPublisher;
                    winningUsers[publisher.LeagueYearKey] = publisher.User;
                }
            }
        }

        return new YearCalculatedStatsSet(publisherGameCalculatedStats, winningUsers);
    }

    public async Task UpdatePublisherGameCalculatedStats(LeagueYear leagueYear)
    {
        Dictionary<Guid, PublisherGameCalculatedStats> calculatedStats = new Dictionary<Guid, PublisherGameCalculatedStats>();

        var currentDate = _clock.GetToday();
        foreach (var publisher in leagueYear.Publishers)
        {
            var slots = publisher.GetPublisherSlots(leagueYear.Options);
            var slotsThatHaveGames = slots.Where(x => x.PublisherGame is not null).ToList();
            foreach (var publisherSlot in slotsThatHaveGames)
            {
                //Before 2022, games that were 'ineligible' still gave points. It was just a warning.
                var ineligiblePointsShouldCount = !SupportedYear.Year2022FeatureSupported(leagueYear.Year);
                var gameIsEligible = publisherSlot.SlotIsValid(leagueYear);
                var pointsShouldCount = gameIsEligible || ineligiblePointsShouldCount;

                decimal? fantasyPoints = publisherSlot.GetFantasyPoints(pointsShouldCount, leagueYear.Options.ScoringSystem, currentDate);
                var stats = new PublisherGameCalculatedStats(fantasyPoints);
                calculatedStats.Add(publisherSlot.PublisherGame!.PublisherGameID, stats);
            }
        }

        await _fantasyCriticRepo.UpdatePublisherGameCalculatedStats(calculatedStats);
    }

    public Task ManuallyScoreGame(PublisherGame publisherGame, decimal? manualCriticScore)
    {
        return _fantasyCriticRepo.ManuallyScoreGame(publisherGame, manualCriticScore);
    }

    public async Task ManuallySetWillNotRelease(LeagueYear leagueYear, PublisherGame publisherGame, bool willNotRelease)
    {
        await _fantasyCriticRepo.ManuallySetWillNotRelease(publisherGame, willNotRelease);
        var managerPublisher = leagueYear.GetManagerPublisherOrThrow();

        string description;
        if (willNotRelease)
        {
            description = $"{publisherGame.GameName}' was manually set as 'Will Not Release'.";
        }
        else
        {
            description = $"{publisherGame.GameName}'s manual 'Will Not Release' setting was cleared.";
        }

        LeagueAction eligibilityAction = new LeagueAction(managerPublisher, _clock.GetCurrentInstant(), "'Will not release' Overridden", description, true);
        await _fantasyCriticRepo.AddLeagueAction(eligibilityAction);
    }

    public Task<IReadOnlyList<LeagueAction>> GetLeagueActions(LeagueYear leagueYear)
    {
        return _fantasyCriticRepo.GetLeagueActions(leagueYear);
    }

    public async Task<IReadOnlyList<LeagueActionProcessingSet>> GetLeagueActionProcessingSets(LeagueYear leagueYear)
    {
        var processSets = await _interLeagueService.GetActionProcessingSets();
        var bidsForLeague = await _fantasyCriticRepo.GetProcessedPickupBids(leagueYear);
        var dropsForLeague = await _fantasyCriticRepo.GetProcessedDropRequests(leagueYear);
        var bidsByProcessSet = bidsForLeague.ToLookup(x => x.ProcessSetID);
        var dropsByProcessSet = dropsForLeague.ToLookup(x => x.ProcessSetID);

        List<LeagueActionProcessingSet> processingSets = new List<LeagueActionProcessingSet>();
        foreach (var processSet in processSets)
        {
            var bids = bidsByProcessSet[processSet.ProcessSetID];
            var drops = dropsByProcessSet[processSet.ProcessSetID];
            processingSets.Add(new LeagueActionProcessingSet(leagueYear, processSet.ProcessSetID, processSet.ProcessTime, processSet.ProcessName, drops, bids));
        }

        return processingSets;
    }

    public Task ChangeLeagueOptions(League league, string leagueName, bool publicLeague, bool testLeague)
    {
        return _fantasyCriticRepo.ChangeLeagueOptions(league, leagueName, publicLeague, testLeague);
    }

    public async Task DeleteLeague(League league)
    {
        var invites = await _fantasyCriticRepo.GetOutstandingInvitees(league);
        foreach (var invite in invites)
        {
            await _fantasyCriticRepo.DeleteInvite(invite);
        }

        foreach (var year in league.Years)
        {
            var leagueYear = await _fantasyCriticRepo.GetLeagueYearOrThrow(league, year);
            var publishers = leagueYear.Publishers;
            foreach (var publisher in publishers)
            {
                await _fantasyCriticRepo.DeleteLeagueActions(publisher);
                foreach (var game in publisher.PublisherGames)
                {
                    await _fantasyCriticRepo.FullyRemovePublisherGame(leagueYear, publisher, game);
                }

                var bids = await _fantasyCriticRepo.GetActivePickupBids(leagueYear, publisher);
                foreach (var bid in bids)
                {
                    await _fantasyCriticRepo.RemovePickupBid(bid);
                }

                var dropRequests = await _fantasyCriticRepo.GetActiveDropRequests(leagueYear, publisher);
                foreach (var dropRequest in dropRequests)
                {
                    await _fantasyCriticRepo.RemoveDropRequest(dropRequest);
                }

                await _fantasyCriticRepo.DeletePublisher(publisher);
            }

            await _fantasyCriticRepo.DeleteLeagueYear(leagueYear);
        }

        var users = await _fantasyCriticRepo.GetUsersInLeague(league.LeagueID);
        foreach (var user in users)
        {
            await _fantasyCriticRepo.RemovePlayerFromLeague(league, user);
        }

        await _fantasyCriticRepo.DeleteLeague(league);
    }

    public Task<IReadOnlyList<League>> GetFollowedLeagues(FantasyCriticUser currentUser)
    {
        return _fantasyCriticRepo.GetFollowedLeagues(currentUser);
    }

    public Task<IReadOnlyList<FantasyCriticUser>> GetLeagueFollowers(League league)
    {
        return _fantasyCriticRepo.GetLeagueFollowers(league);
    }

    public async Task<Result> FollowLeague(League league, FantasyCriticUser user)
    {
        if (!league.PublicLeague)
        {
            return Result.Failure("League is not public");
        }

        bool userIsInLeague = await _leagueMemberService.UserIsInLeague(league, user);
        if (userIsInLeague)
        {
            return Result.Failure("Can't follow a league you are in.");
        }

        var followedLeagues = await GetFollowedLeagues(user);
        bool userIsFollowingLeague = followedLeagues.Any(x => x.LeagueID == league.LeagueID);
        if (userIsFollowingLeague)
        {
            return Result.Failure("User is already following that league.");
        }

        await _fantasyCriticRepo.FollowLeague(league, user);
        return Result.Success();
    }

    public async Task<Result> UnfollowLeague(League league, FantasyCriticUser user)
    {
        var followedLeagues = await GetFollowedLeagues(user);
        bool userIsFollowingLeague = followedLeagues.Any(x => x.LeagueID == league.LeagueID);
        if (!userIsFollowingLeague)
        {
            return Result.Failure("User is not following that league.");
        }

        await _fantasyCriticRepo.UnfollowLeague(league, user);
        return Result.Success();
    }

    public async Task<IReadOnlyList<LeagueYear>> GetPublicLeagueYears(int year)
    {
        var leagueYears = await _fantasyCriticRepo.GetLeagueYears(year);
        return leagueYears.Where(x => x.League.PublicLeague).OrderByDescending(x => x.League.NumberOfFollowers).ToList();
    }

    public async Task SetEligibilityOverride(LeagueYear leagueYear, MasterGame masterGame, bool? eligible)
    {
        if (!eligible.HasValue)
        {
            await _fantasyCriticRepo.DeleteEligibilityOverride(leagueYear, masterGame);
        }
        else
        {
            await _fantasyCriticRepo.SetEligibilityOverride(leagueYear, masterGame, eligible.Value);
        }

        var managerPublisher = leagueYear.GetManagerPublisherOrThrow();
        string description;
        if (!eligible.HasValue)
        {
            description = $"{masterGame.GameName}'s eligibility setting was reset to normal.";
        }
        else if (eligible.Value)
        {
            description = $"{masterGame.GameName} was manually set to 'Eligible'";
        }
        else
        {
            description = $"{masterGame.GameName} was manually set to 'Ineligible'";
        }

        LeagueAction eligibilityAction = new LeagueAction(managerPublisher, _clock.GetCurrentInstant(), "Eligibility Setting Changed", description, true);
        await _fantasyCriticRepo.AddLeagueAction(eligibilityAction);
    }

    public Task<IReadOnlyList<TagOverride>> GetTagOverrides(League league, int year)
    {
        return _fantasyCriticRepo.GetTagOverrides(league, year);
    }

    public Task<IReadOnlyList<MasterGameTag>> GetTagOverridesForGame(League league, int year, MasterGame masterGame)
    {
        return _fantasyCriticRepo.GetTagOverridesForGame(league, year, masterGame);
    }

    public async Task SetTagOverride(LeagueYear leagueYear, MasterGame masterGame, List<MasterGameTag> requestedTags)
    {
        await _fantasyCriticRepo.SetTagOverride(leagueYear, masterGame, requestedTags);
        var managerPublisher = leagueYear.GetManagerPublisherOrThrow();
        if (requestedTags.Any())
        {
            var tagNames = string.Join(", ", requestedTags.Select(x => x.ReadableName));
            string description = $"{masterGame.GameName}'s tags were set to: '{tagNames}'.";
            LeagueAction tagAction = new LeagueAction(managerPublisher, _clock.GetCurrentInstant(), "Tags Overriden", description, true);
            await _fantasyCriticRepo.AddLeagueAction(tagAction);
        }
        else
        {
            string description = $"{masterGame.GameName}'s tags were reset to default.";
            LeagueAction tagAction = new LeagueAction(managerPublisher, _clock.GetCurrentInstant(), "Tags Override Cleared", description, true);
            await _fantasyCriticRepo.AddLeagueAction(tagAction);
        }
    }

    public async Task PostNewManagerMessage(LeagueYear leagueYear, string message, bool isPublic)
    {
        var domainMessage = new ManagerMessage(Guid.NewGuid(), message, isPublic, _clock.GetCurrentInstant(), new List<Guid>());
        await _fantasyCriticRepo.PostNewManagerMessage(leagueYear, domainMessage);
    }

    public Task<IReadOnlyList<ManagerMessage>> GetManagerMessages(LeagueYear leagueYear)
    {
        return _fantasyCriticRepo.GetManagerMessages(leagueYear);
    }

    public Task<Result> DeleteManagerMessage(LeagueYear leagueYear, Guid messageID)
    {
        return _fantasyCriticRepo.DeleteManagerMessage(leagueYear, messageID);
    }

    public Task<Result> DismissManagerMessage(Guid messageID, Guid userID)
    {
        return _fantasyCriticRepo.DismissManagerMessage(messageID, userID);
    }

    public Task<FantasyCriticUser?> GetPreviousYearWinner(LeagueYear leagueYear)
    {
        int previousYear = leagueYear.Year - 1;
        return _fantasyCriticRepo.GetLeagueYearWinner(leagueYear.League.LeagueID, previousYear);
    }

    public async Task<Result> ProposeTrade(LeagueYear leagueYear, Publisher proposer, Guid counterPartyPublisherID, IReadOnlyList<Guid> proposerPublisherGameIDs,
        IReadOnlyList<Guid> counterPartyPublisherGameIDs, uint proposerBudgetSendAmount, uint counterPartyBudgetSendAmount, string message)
    {
        if (leagueYear.Options.TradingSystem.Equals(TradingSystem.NoTrades))
        {
            return Result.Failure("Trades are not enabled for this league year.");
        }

        if (string.IsNullOrWhiteSpace(message))
        {
            return Result.Failure("Trades must include a message.");
        }

        if (proposerBudgetSendAmount > 0 && counterPartyBudgetSendAmount > 0)
        {
            return Result.Failure("You cannot have budget on both sides of the trade.");
        }

        if (!proposerPublisherGameIDs.Any() && proposerBudgetSendAmount == 0)
        {
            return Result.Failure("You must offer something.");
        }

        if (!counterPartyPublisherGameIDs.Any() && counterPartyBudgetSendAmount == 0)
        {
            return Result.Failure("You must receive something.");
        }

        var counterPartyResult = leagueYear.GetPublisherByID(counterPartyPublisherID);
        if (counterPartyResult is null)
        {
            return Result.Failure("That publisher does not exist");
        }
        var counterParty = counterPartyResult;

        if (!leagueYear.Key.Equals(counterParty.LeagueYearKey))
        {
            return Result.Failure("That publisher is not in your league.");
        }

        if (proposerBudgetSendAmount > proposer.Budget)
        {
            return Result.Failure("You do not have enough budget for this trade.");
        }

        if (counterPartyBudgetSendAmount > counterParty.Budget)
        {
            return Result.Failure("The other publisher does not have enough budget for this trade.");
        }

        var proposerPublisherGames = proposer.PublisherGames.Where(x => proposerPublisherGameIDs.Contains(x.PublisherGameID)).ToList();
        var counterPartyPublisherGames = counterParty.PublisherGames.Where(x => counterPartyPublisherGameIDs.Contains(x.PublisherGameID)).ToList();
        if (proposerPublisherGames.Count != proposerPublisherGameIDs.Count)
        {
            return Result.Failure("Some of the proposer publisher games are invalid or duplicates.");
        }

        if (counterPartyPublisherGames.Count != counterPartyPublisherGameIDs.Count)
        {
            return Result.Failure("Some of the counter party publisher games are invalid or duplicates.");
        }

        var proposerPublisherGamesWithMasterGames = proposerPublisherGames.Select(x => x.GetMasterGameYearWithCounterPick()).Where(x => x is not null).Select(x => x!).ToList();
        var counterPartyPublisherGamesWithMasterGames = counterPartyPublisherGames.Select(x => x.GetMasterGameYearWithCounterPick()).Where(x => x is not null).Select(x => x!).ToList();
        if (proposerPublisherGamesWithMasterGames.Count != proposerPublisherGameIDs.Count)
        {
            return Result.Failure("All games in a trade must be linked to a master game.");
        }

        if (counterPartyPublisherGamesWithMasterGames.Count != counterPartyPublisherGameIDs.Count)
        {
            return Result.Failure("All games in a trade must be linked to a master game.");
        }

        Trade trade = new Trade(Guid.NewGuid(), leagueYear, proposer, counterParty, proposerPublisherGamesWithMasterGames,
            counterPartyPublisherGamesWithMasterGames,
            proposerBudgetSendAmount, counterPartyBudgetSendAmount, message, _clock.GetCurrentInstant(), null, null,
            new List<TradeVote>(), TradeStatus.Proposed);

        var tradeError = trade.GetTradeError();
        if (tradeError is not null)
        {
            return Result.Failure(tradeError);
        }

        await _fantasyCriticRepo.CreateTrade(trade);

        return Result.Success();
    }

    public Task<Trade?> GetTrade(Guid tradeID)
    {
        return _fantasyCriticRepo.GetTrade(tradeID);
    }

    public async Task<IReadOnlyList<Trade>> GetTradesForLeague(LeagueYear leagueYear)
    {
        var trades = await _fantasyCriticRepo.GetTradesForLeague(leagueYear);
        return trades;
    }

    public async Task<IReadOnlyList<Trade>> GetActiveTradesForLeague(LeagueYear leagueYear)
    {
        var allTrades = await GetTradesForLeague(leagueYear);
        var activeTrades = allTrades.Where(x => x.Status.IsActive).ToList();
        return activeTrades;
    }

    public async Task<Result> RescindTrade(Trade trade)
    {
        if (!trade.Status.IsActive)
        {
            return Result.Failure("That trade cannot be rescinded as it is no longer active.");
        }

        var now = _clock.GetCurrentInstant();
        await _fantasyCriticRepo.EditTradeStatus(trade, TradeStatus.Rescinded, null, now);
        return Result.Success();
    }

    public async Task<Result> AcceptTrade(Trade trade)
    {
        if (!trade.Status.IsActive)
        {
            return Result.Failure("That trade cannot be accepted as it is no longer active.");
        }

        var now = _clock.GetCurrentInstant();
        await _fantasyCriticRepo.EditTradeStatus(trade, TradeStatus.Accepted, now, null);
        return Result.Success();
    }

    public async Task<Result> RejectTradeByCounterParty(Trade trade)
    {
        if (!trade.Status.IsActive)
        {
            return Result.Failure("That trade cannot be rejected as it is no longer active.");
        }

        var now = _clock.GetCurrentInstant();
        await _fantasyCriticRepo.EditTradeStatus(trade, TradeStatus.RejectedByCounterParty, null, now);
        return Result.Success();
    }

    public async Task<Result> RejectTradeByManager(Trade trade)
    {
        if (!trade.Status.IsActive)
        {
            return Result.Failure("That trade cannot be rejected as it is no longer active.");
        }

        var now = _clock.GetCurrentInstant();
        await _fantasyCriticRepo.EditTradeStatus(trade, TradeStatus.RejectedByManager, null, now);
        return Result.Success();
    }

    public async Task<Result> VoteOnTrade(Trade trade, FantasyCriticUser user, bool approved, string? comment)
    {
        var alreadyVoted = trade.TradeVotes.Select(x => x.User.Id).ToHashSet().Contains(user.Id);
        if (alreadyVoted)
        {
            return Result.Failure("You have already vote on this trade.");
        }

        var tradeVote = new TradeVote(trade.TradeID, user, approved, comment, _clock.GetCurrentInstant());
        await _fantasyCriticRepo.AddTradeVote(tradeVote);
        return Result.Success();
    }

    public async Task<Result> DeleteTradeVote(Trade trade, FantasyCriticUser user)
    {
        var alreadyVoted = trade.TradeVotes.Select(x => x.User.Id).ToHashSet().Contains(user.Id);
        if (!alreadyVoted)
        {
            return Result.Failure("You have note voted on this trade.");
        }

        await _fantasyCriticRepo.DeleteTradeVote(trade, user);
        return Result.Success();
    }

    public async Task<Result> ExecuteTrade(Trade trade)
    {
        if (!trade.Status.Equals(TradeStatus.Accepted))
        {
            return Result.Failure("Only accepted trades can be executed.");
        }

        var tradeError = trade.GetTradeError();
        if (tradeError is not null)
        {
            return Result.Failure(tradeError);
        }

        var completionTime = _clock.GetCurrentInstant();
        var newPublisherGamesResult = trade.GetNewPublisherGamesFromTrade(completionTime);
        if (newPublisherGamesResult.IsFailure)
        {
            return Result.Failure(newPublisherGamesResult.Error);
        }

        var executedTrade = new ExecutedTrade(trade, completionTime, newPublisherGamesResult.Value);
        await _fantasyCriticRepo.ExecuteTrade(executedTrade);
        return Result.Success();
    }
}
