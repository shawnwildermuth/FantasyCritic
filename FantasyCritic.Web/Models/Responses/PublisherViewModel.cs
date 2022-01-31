using System;
using System.Collections.Generic;
using System.Linq;
using CSharpFunctionalExtensions;
using FantasyCritic.Lib.Domain;
using FantasyCritic.Lib.Domain.ScoringSystems;
using NodaTime;

namespace FantasyCritic.Web.Models.Responses
{
    public class PublisherViewModel
    {
        public PublisherViewModel(Publisher publisher, LocalDate currentDate, bool userIsInLeague,
            bool outstandingInvite, SystemWideValues systemWideValues, bool yearFinished, IReadOnlySet<Guid> counterPickedPublisherGameIDs)
        : this(publisher, currentDate, Maybe<Publisher>.None, userIsInLeague, outstandingInvite, systemWideValues, yearFinished, counterPickedPublisherGameIDs)
        {

        }

        public PublisherViewModel(Publisher publisher, LocalDate currentDate, Maybe<Publisher> nextDraftPublisher,
            bool userIsInLeague, bool outstandingInvite, SystemWideValues systemWideValues, bool yearFinished, IReadOnlySet<Guid> counterPickedPublisherGameIDs)
        {
            PublisherID = publisher.PublisherID;
            LeagueID = publisher.LeagueYear.League.LeagueID;
            UserID = publisher.User.Id;
            PublisherName = publisher.PublisherName;
            PublisherIcon = publisher.PublisherIcon.GetValueOrDefault();
            LeagueName = publisher.LeagueYear.League.LeagueName;
            PlayerName = publisher.User.UserName;
            Year = publisher.LeagueYear.Year;
            DraftPosition = publisher.DraftPosition;
            AutoDraft = publisher.AutoDraft;
            Games = publisher.PublisherGames
                .OrderBy(x => x.Timestamp)
                .Select(x => new PublisherGameViewModel(x, currentDate, counterPickedPublisherGameIDs.Contains(x.PublisherGameID), publisher.LeagueYear.Options.CounterPicksBlockDrops))
                .ToList();

            GameSlots = publisher.GetPublisherSlots()
                .Select(x => new PublisherSlotViewModel(publisher.LeagueYear.Year, x, currentDate, publisher.LeagueYear, systemWideValues, counterPickedPublisherGameIDs))
                .ToList();

            AverageCriticScore = publisher.AverageCriticScore;
            TotalFantasyPoints = publisher.TotalFantasyPoints;

            var ineligiblePointsShouldCount = !SupportedYear.Year2022FeatureSupported(publisher.LeagueYear.Year);
            TotalProjectedPoints = publisher.GetProjectedFantasyPoints(systemWideValues, false, currentDate, ineligiblePointsShouldCount);
            Budget = publisher.Budget;

            if (nextDraftPublisher.HasValue && nextDraftPublisher.Value.PublisherID == publisher.PublisherID)
            {
                NextToDraft = true;
            }

            UserIsInLeague = userIsInLeague;
            PublicLeague = publisher.LeagueYear.Options.PublicLeague;
            OutstandingInvite = outstandingInvite;

            var dateToCheck = currentDate;
            if (yearFinished)
            {
                dateToCheck = new LocalDate(Year, 12, 31);
            }

            GamesReleased = publisher.PublisherGames
                .Where(x => !x.CounterPick)
                .Where(x => x.MasterGame.HasValue)
                .Count(x => x.MasterGame.Value.MasterGame.IsReleased(dateToCheck));
            var allWillRelease = publisher.PublisherGames
                .Where(x => !x.CounterPick)
                .Where(x => x.MasterGame.HasValue)
                .Count(x => x.WillRelease());
            GamesWillRelease = allWillRelease - GamesReleased;

            FreeGamesDropped = publisher.FreeGamesDropped;
            WillNotReleaseGamesDropped = publisher.WillNotReleaseGamesDropped;
            WillReleaseGamesDropped = publisher.WillReleaseGamesDropped;
            FreeDroppableGames = publisher.LeagueYear.Options.FreeDroppableGames;
            WillNotReleaseDroppableGames = publisher.LeagueYear.Options.WillNotReleaseDroppableGames;
            WillReleaseDroppableGames = publisher.LeagueYear.Options.WillReleaseDroppableGames;
        }

        public Guid PublisherID { get; }
        public Guid LeagueID { get; }
        public Guid UserID { get; }
        public string PublisherName { get; }
        public string PublisherIcon { get; }
        public string LeagueName { get; }
        public string PlayerName { get; }
        public int Year { get; }
        public int DraftPosition { get; }
        public bool AutoDraft { get; }
        public IReadOnlyList<PublisherGameViewModel> Games { get; }
        public IReadOnlyList<PublisherSlotViewModel> GameSlots { get; }
        public decimal? AverageCriticScore { get; }
        public decimal TotalFantasyPoints { get; }
        public decimal TotalProjectedPoints { get; }
        public uint Budget { get; }
        public bool NextToDraft { get; }
        public bool UserIsInLeague { get; }
        public bool PublicLeague { get; }
        public bool OutstandingInvite { get; }

        public int GamesReleased { get; }
        public int GamesWillRelease { get; }
        public int FreeGamesDropped { get; }
        public int WillNotReleaseGamesDropped { get; }
        public int WillReleaseGamesDropped { get; }
        public int FreeDroppableGames { get; }
        public int WillNotReleaseDroppableGames { get; }
        public int WillReleaseDroppableGames { get; }
    }
}
