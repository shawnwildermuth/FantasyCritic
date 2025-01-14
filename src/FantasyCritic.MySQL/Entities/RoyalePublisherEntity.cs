using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Royale;

namespace FantasyCritic.MySQL.Entities;

internal class RoyalePublisherEntity
{
    public RoyalePublisherEntity()
    {

    }

    public RoyalePublisherEntity(RoyalePublisher domainRoyalePublisher)
    {
        PublisherID = domainRoyalePublisher.PublisherID;
        UserID = domainRoyalePublisher.User.Id;
        Year = domainRoyalePublisher.YearQuarter.YearQuarter.Year;
        Quarter = domainRoyalePublisher.YearQuarter.YearQuarter.Quarter;
        PublisherName = domainRoyalePublisher.PublisherName;
        PublisherIcon = domainRoyalePublisher.PublisherIcon;
        Budget = domainRoyalePublisher.Budget;
    }

    public Guid PublisherID { get; set; }
    public Guid UserID { get; set; }
    public int Year { get; set; }
    public int Quarter { get; set; }
    public string PublisherName { get; set; } = null!;
    public string? PublisherIcon { get; set; }
    public decimal Budget { get; set; }

    public RoyalePublisher ToDomain(RoyaleYearQuarter royaleYearQuarter, FantasyCriticUser user, IEnumerable<RoyalePublisherGame> publisherGames)
    {
        return new RoyalePublisher(PublisherID, royaleYearQuarter, user, PublisherName, PublisherIcon, publisherGames, Budget);
    }
}
