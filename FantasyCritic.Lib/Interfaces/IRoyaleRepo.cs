﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using FantasyCritic.Lib.Domain;
using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Royale;

namespace FantasyCritic.Lib.Interfaces
{
    public interface IRoyaleRepo
    {
        Task CreatePublisher(RoyalePublisher publisher);
        Task<Maybe<RoyalePublisher>> GetPublisher(RoyaleYearQuarter yearQuarter, FantasyCriticUser user);
        Task<IReadOnlyList<RoyaleYearQuarter>> GetYearQuarters();
        Task<Maybe<RoyalePublisher>> GetPublisher(Guid publisherID);
        Task PurchaseGame(RoyalePublisherGame game);
        Task SellGame(RoyalePublisherGame publisherGame, bool fullRefund);
        Task SetAdvertisingMoney(RoyalePublisherGame publisherGame, decimal advertisingMoney);
        Task<IReadOnlyList<RoyalePublisher>> GetAllPublishers(int year, int quarter);
        Task UpdateFantasyPoints(Dictionary<(Guid, Guid), decimal?> publisherGameScores);
        Task ChangePublisherName(RoyalePublisher publisher, string publisherName);
        Task<IReadOnlyList<RoyaleYearQuarter>> GetQuartersWonByUser(FantasyCriticUser user);
        Task<IReadOnlyDictionary<FantasyCriticUser, IReadOnlyList<RoyaleYearQuarter>>> GetRoyaleWinners();
        Task StartNewQuarter(YearQuarter nextQuarter);
        Task FinishQuarter(RoyaleYearQuarter supportedQuarter);
    }
}
