using FantasyCritic.Lib.Domain.LeagueActions;

namespace FantasyCritic.Web.Models.Responses;

public class LeagueActionProcessingSetViewModel
{
    public LeagueActionProcessingSetViewModel(LeagueActionProcessingSet domain, LocalDate currentDate)
    {
        LeagueID = domain.LeagueYear.League.LeagueID;
        LeagueName = domain.LeagueYear.League.LeagueName;
        Year = domain.LeagueYear.Year;
        ProcessSetID = domain.ProcessSetID;
        ProcessTime = domain.ProcessTime;
        ProcessName = domain.ProcessName;
        Drops = domain.Drops.Select(x => new DropGameRequestViewModel(x, currentDate)).ToList();
        Bids = domain.Bids.Select(x => new PickupBidViewModel(x, currentDate)).ToList();
    }

    public Guid LeagueID { get; }
    public string LeagueName { get; }
    public int Year { get; }
    public Guid ProcessSetID { get; }
    public Instant ProcessTime { get; }
    public string ProcessName { get; }
    public IReadOnlyList<DropGameRequestViewModel> Drops { get; }
    public IReadOnlyList<PickupBidViewModel> Bids { get; }
}
