﻿using FantasyCritic.Lib.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using FantasyCritic.Lib.Domain;
using FantasyCritic.Lib.Domain.Results;
using FantasyCritic.Lib.Domain.ScoringSystems;
using FantasyCritic.Lib.Extensions;
using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Royale;
using MoreLinq;
using NLog.Targets.Wrappers;
using NodaTime;

namespace FantasyCritic.Lib.Services
{
    public class RoyaleService
    {
        private readonly IRoyaleRepo _royaleRepo;
        private readonly IClock _clock;
        private readonly IMasterGameRepo _masterGameRepo;

        public const int MAX_GAMES = 25;

        public RoyaleService(IRoyaleRepo royaleRepo, IClock clock, IMasterGameRepo masterGameRepo)
        {
            _royaleRepo = royaleRepo;
            _clock = clock;
            _masterGameRepo = masterGameRepo;
        }

        public Task<IReadOnlyList<RoyaleYearQuarter>> GetYearQuarters()
        {
            return _royaleRepo.GetYearQuarters();
        }

        public async Task<RoyaleYearQuarter> GetActiveYearQuarter()
        {
            IReadOnlyList<RoyaleYearQuarter> supportedQuarters = await GetYearQuarters();
            var activeQuarter = supportedQuarters.Where(x => x.OpenForPlay).MaxBy(x => x.YearQuarter).Single();
            return activeQuarter;
        }

        public async Task<Maybe<RoyaleYearQuarter>> GetYearQuarter(int year, int quarter)
        {
            IReadOnlyList<RoyaleYearQuarter> supportedQuarters = await GetYearQuarters();
            var requestedQuarter = supportedQuarters.SingleOrDefault(x => x.YearQuarter.Year == year && x.YearQuarter.Quarter == quarter);
            return requestedQuarter;
        }

        public async Task<RoyalePublisher> CreatePublisher(RoyaleYearQuarter yearQuarter, FantasyCriticUser user, string publisherName)
        {
            RoyalePublisher publisher = new RoyalePublisher(Guid.NewGuid(), yearQuarter, user, publisherName, new List<RoyalePublisherGame>(), 100m);
            await _royaleRepo.CreatePublisher(publisher);
            return publisher;
        }

        public Task ChangePublisherName(RoyalePublisher publisher, string publisherName)
        {
            return _royaleRepo.ChangePublisherName(publisher, publisherName);
        }

        public Task<Maybe<RoyalePublisher>> GetPublisher(RoyaleYearQuarter yearQuarter, FantasyCriticUser user)
        {
            return _royaleRepo.GetPublisher(yearQuarter, user);
        }

        public Task<Maybe<RoyalePublisher>> GetPublisher(Guid publisherID)
        {
            return _royaleRepo.GetPublisher(publisherID);
        }

        public Task<IReadOnlyList<RoyalePublisher>> GetAllPublishers(int year, int quarter)
        {
            return _royaleRepo.GetAllPublishers(year, quarter);
        }

        public async Task<IReadOnlyList<MasterGameYear>> GetMasterGamesForYearQuarter(YearQuarter yearQuarter)
        {
            IEnumerable<MasterGameYear> masterGameYears = await _masterGameRepo.GetMasterGameYears(yearQuarter.Year);

            var currentDate = _clock.GetToday();
            masterGameYears = masterGameYears.Where(x => !x.MasterGame.ReleaseDate.HasValue || x.MasterGame.ReleaseDate >= yearQuarter.FirstDateOfQuarter);
            masterGameYears = masterGameYears.OrderByDescending(x => x.GetProjectedOrRealFantasyPoints(ScoringSystem.GetDefaultScoringSystem(yearQuarter.Year), false, currentDate));

            return masterGameYears.ToList();
        }

        public async Task<ClaimResult> PurchaseGame(RoyalePublisher publisher, MasterGameYear masterGame)
        {
            if (publisher.PublisherGames.Count >= MAX_GAMES)
            {
                return new ClaimResult("Roster is full.", null);
            }
            if (publisher.PublisherGames.Select(x => x.MasterGame).Contains(masterGame))
            {
                return new ClaimResult("Publisher already has that game.", null);
            }
            if (!masterGame.WillReleaseInQuarter(publisher.YearQuarter.YearQuarter))
            {
                return new ClaimResult("Game will not release this quarter.", null);
            }

            var now = _clock.GetCurrentInstant();
            var currentDate = now.ToEasternDate();
            if (masterGame.MasterGame.IsReleased(currentDate))
            {
                return new ClaimResult("Game has been released.", null);
            }
            if (masterGame.MasterGame.CriticScore.HasValue)
            {
                return new ClaimResult("Game has a score.", null);
            }

            var masterGameTags = await _masterGameRepo.GetMasterGameTags();
            var eligibilityErrors = LeagueTagExtensions.GetRoyaleClaimErrors(masterGameTags, masterGame.MasterGame, currentDate);
            if (eligibilityErrors.Any())
            {
                return new ClaimResult("Game is not eligible under Royale rules.", null);
            }

            var currentBudget = publisher.Budget;
            var gameCost = masterGame.GetRoyaleGameCost();
            if (currentBudget < gameCost)
            {
                return new ClaimResult("Not enough budget.", null);
            }

            RoyalePublisherGame game = new RoyalePublisherGame(publisher.PublisherID, publisher.YearQuarter, masterGame, now, gameCost, 0m, null);
            await _royaleRepo.PurchaseGame(game);
            var nextSlot = publisher.PublisherGames.Count;
            return new ClaimResult(nextSlot);
        }

        public async Task<Result> SellGame(RoyalePublisher publisher, RoyalePublisherGame publisherGame)
        {
            var currentDate = _clock.GetToday();
            if (publisherGame.MasterGame.MasterGame.IsReleased(currentDate))
            {
                return Result.Failure("That game has already been released.");
            }
            if (publisherGame.MasterGame.MasterGame.CriticScore.HasValue)
            {
                return Result.Failure("That game already has a score.");
            }

            if (!publisher.PublisherGames.Contains(publisherGame))
            {
                return Result.Failure("You don't have that game.");
            }

            var masterGameTags = await _masterGameRepo.GetMasterGameTags();
            var currentlyInEligible = publisherGame.CalculateIsCurrentlyIneligible(masterGameTags);
            await _royaleRepo.SellGame(publisherGame, currentlyInEligible);
            return Result.Success();
        }

        public async Task<Result> SetAdvertisingMoney(RoyalePublisher publisher, RoyalePublisherGame publisherGame, decimal advertisingMoney)
        {
            var currentDate = _clock.GetToday();
            if (publisherGame.MasterGame.MasterGame.IsReleased(currentDate))
            {
                return Result.Failure("That game has already been released.");
            }

            if (publisherGame.MasterGame.MasterGame.CriticScore.HasValue)
            {
                return Result.Failure("That game already has a score.");
            }

            if (!publisher.PublisherGames.Contains(publisherGame))
            {
                return Result.Failure("You don't have that game.");
            }

            decimal newDollarsToSpend = advertisingMoney - publisherGame.AdvertisingMoney;
            if (publisher.Budget < newDollarsToSpend)
            {
                return Result.Failure("You don't have enough money.");
            }

            if (advertisingMoney < 0m)
            {
                return Result.Failure("You can't allocate negative dollars in advertising money.");
            }

            if (advertisingMoney > 10m)
            {
                return Result.Failure("You can't allocate more than 10 dollars in advertising money.");
            }

            await _royaleRepo.SetAdvertisingMoney(publisherGame, advertisingMoney);
            return Result.Success();
        }

        public async Task UpdateFantasyPoints(YearQuarter yearQuarter)
        {
            Dictionary<(Guid, Guid), decimal?> publisherGameScores = new Dictionary<(Guid, Guid), decimal?>();
            var allPublishersForQuarter = await _royaleRepo.GetAllPublishers(yearQuarter.Year, yearQuarter.Quarter);

            var allMasterGameTags = await _masterGameRepo.GetMasterGameTags();
            var currentDate = _clock.GetToday();
            foreach (var publisher in allPublishersForQuarter)
            {
                foreach (var publisherGame in publisher.PublisherGames)
                {
                    decimal? fantasyPoints = publisherGame.CalculateFantasyPoints(currentDate, allMasterGameTags);
                    publisherGameScores.Add((publisherGame.PublisherID, publisherGame.MasterGame.MasterGame.MasterGameID), fantasyPoints);
                }
            }

            await _royaleRepo.UpdateFantasyPoints(publisherGameScores);
        }

        public Task<IReadOnlyList<RoyaleYearQuarter>> GetQuartersWonByUser(FantasyCriticUser user)
        {
            return _royaleRepo.GetQuartersWonByUser(user);
        }

        public Task<IReadOnlyDictionary<FantasyCriticUser, IReadOnlyList<RoyaleYearQuarter>>> GetRoyaleWinners()
        {
            return _royaleRepo.GetRoyaleWinners();
        }

        public Task StartNewQuarter(YearQuarter nextQuarter)
        {
            return _royaleRepo.StartNewQuarter(nextQuarter);
        }

        public Task FinishQuarter(RoyaleYearQuarter supportedQuarter)
        {
            return _royaleRepo.FinishQuarter(supportedQuarter);
        }
    }
}
