using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Utilities;

namespace FantasyCritic.Lib.Email.EmailModels;

public class PublicBidEmailModel
{
    public PublicBidEmailModel(FantasyCriticUser user, IReadOnlyList<PublicBiddingSet> publicBiddingSets, string baseAddress, bool isProduction)
    {
        User = user;
        PublicBiddingSets = publicBiddingSets;
        BaseAddress = baseAddress;
        PublicBiddingSetsByYear = publicBiddingSets.GroupToDictionary(x => x.LeagueYear.Year);
        IsProduction = isProduction;
    }

    public FantasyCriticUser User { get; }
    public IReadOnlyList<PublicBiddingSet> PublicBiddingSets { get; }
    public string BaseAddress { get; }
    public bool IsProduction { get; }

    public IReadOnlyDictionary<int, IReadOnlyList<PublicBiddingSet>> PublicBiddingSetsByYear { get; }
    public bool ShowMultiYear => PublicBiddingSets.Count > 1;

    public string GetLeagueLink(LeagueYearKey key) => $"{BaseAddress}/league/{key.LeagueID}/{key.Year}";
    public string GetManageAccountLink() => $"{BaseAddress}/Identity/Account/Manage/Email";
}
