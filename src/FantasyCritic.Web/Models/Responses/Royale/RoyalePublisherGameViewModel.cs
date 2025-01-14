using FantasyCritic.Lib.Royale;

namespace FantasyCritic.Web.Models.Responses.Royale;

public class RoyalePublisherGameViewModel
{
    public RoyalePublisherGameViewModel(RoyalePublisherGame domain, LocalDate currentDate, IEnumerable<MasterGameTag> allMasterGameTags)
    {
        PublisherID = domain.PublisherID;
        YearQuarter = new RoyaleYearQuarterViewModel(domain.YearQuarter);
        MasterGame = new MasterGameYearViewModel(domain.MasterGame, currentDate);
        Locked = domain.IsLocked(currentDate, allMasterGameTags);
        Timestamp = domain.Timestamp;
        AmountSpent = domain.AmountSpent;
        AdvertisingMoney = domain.AdvertisingMoney;
        FantasyPoints = domain.FantasyPoints;
        CurrentlyIneligible = domain.CalculateIsCurrentlyIneligible(allMasterGameTags);
        RefundAmount = AmountSpent;
        if (!CurrentlyIneligible)
        {
            RefundAmount /= 2;
        }
    }

    public Guid PublisherID { get; }
    public RoyaleYearQuarterViewModel YearQuarter { get; }
    public MasterGameYearViewModel MasterGame { get; }
    public bool Locked { get; }
    public Instant Timestamp { get; }
    public decimal AmountSpent { get; }
    public decimal AdvertisingMoney { get; }
    public decimal? FantasyPoints { get; }
    public bool CurrentlyIneligible { get; }
    public decimal RefundAmount { get; }
}
