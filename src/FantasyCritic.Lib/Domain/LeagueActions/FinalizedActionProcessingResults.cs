using FantasyCritic.Lib.Utilities;

namespace FantasyCritic.Lib.Domain.LeagueActions;

public class FinalizedActionProcessingResults
{
    public FinalizedActionProcessingResults(Guid processSetID, Instant processTime, string processName, ActionProcessingResults results)
    {
        ProcessSetID = processSetID;
        ProcessTime = processTime;
        ProcessName = processName;
        Results = results;
    }

    public Guid ProcessSetID { get; }
    public Instant ProcessTime { get; }
    public string ProcessName { get; }
    public ActionProcessingResults Results { get; }

    public IReadOnlyList<LeagueActionProcessingSet> GetLeagueActionSets(bool dryRun)
    {
        List<DropRequest> allDrops;
        List<PickupBid> allBids;
        if (!dryRun)
        {
            allDrops = Results.SuccessDrops.Concat(Results.FailedDrops).ToList();
            allBids = Results.SuccessBids.Select(x => x.PickupBid).Concat(Results.FailedBids.Select(x => x.PickupBid)).ToList();
        }
        else
        {
            allDrops = new List<DropRequest>();
            foreach (var successDrop in Results.SuccessDrops)
            {
                allDrops.Add(successDrop.ToDropWithSuccess(true, ProcessSetID));
            }
            foreach (var failedDrop in Results.FailedDrops)
            {
                allDrops.Add(failedDrop.ToDropWithSuccess(false, ProcessSetID));
            }

            allBids = new List<PickupBid>();
            foreach (var successBid in Results.SuccessBids)
            {
                allBids.Add(successBid.ToFlatBid(ProcessSetID));
            }
            foreach (var failedBid in Results.FailedBids)
            {
                allBids.Add(failedBid.ToFlatBid(ProcessSetID));
            }
        }
        var bidsByLeague = allBids.GroupToDictionary(x => x.LeagueYear);
        var dropsByLeague = allDrops.ToLookup(x => x.LeagueYear);

        List<LeagueActionProcessingSet> leagueSets = new List<LeagueActionProcessingSet>();
        var leagueYears = bidsByLeague.Keys.ToList();
        foreach (var leagueYear in leagueYears)
        {
            var dropsForLeague = dropsByLeague[leagueYear];
            var bidsForLeague = bidsByLeague[leagueYear];
            leagueSets.Add(new LeagueActionProcessingSet(leagueYear, ProcessSetID, ProcessTime, ProcessName, dropsForLeague, bidsForLeague));
        }

        return leagueSets;
    }
}
