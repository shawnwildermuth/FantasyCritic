using FantasyCritic.Lib.Domain.LeagueActions;
using FantasyCritic.Lib.GG;
using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Interfaces;
using FantasyCritic.Lib.OpenCritic;

namespace FantasyCritic.Lib.Services;

public class InterLeagueService
{
    private readonly IFantasyCriticRepo _fantasyCriticRepo;
    private readonly IMasterGameRepo _masterGameRepo;

    public InterLeagueService(IFantasyCriticRepo fantasyCriticRepo, IMasterGameRepo masterGameRepo)
    {
        _fantasyCriticRepo = fantasyCriticRepo;
        _masterGameRepo = masterGameRepo;
    }

    public Task<SystemWideSettings> GetSystemWideSettings()
    {
        return _fantasyCriticRepo.GetSystemWideSettings();
    }

    public Task<SystemWideValues> GetSystemWideValues()
    {
        return _fantasyCriticRepo.GetSystemWideValues();
    }

    public Task<SiteCounts> GetSiteCounts()
    {
        return _fantasyCriticRepo.GetSiteCounts();
    }

    public Task CreateMasterGame(MasterGame masterGame)
    {
        return _masterGameRepo.CreateMasterGame(masterGame);
    }

    public Task EditMasterGame(MasterGame masterGame)
    {
        return _masterGameRepo.EditMasterGame(masterGame);
    }

    public Task<IReadOnlyList<SupportedYear>> GetSupportedYears()
    {
        return _fantasyCriticRepo.GetSupportedYears();
    }

    public Task<SupportedYear> GetSupportedYear(int year)
    {
        return _fantasyCriticRepo.GetSupportedYear(year);
    }

    public Task<IReadOnlyList<MasterGame>> GetMasterGames()
    {
        return _masterGameRepo.GetMasterGames();
    }

    public Task<IReadOnlyList<MasterGameYear>> GetMasterGameYears(int year)
    {
        return _masterGameRepo.GetMasterGameYears(year);
    }

    public Task<MasterGame?> GetMasterGame(Guid masterGameID)
    {
        return _masterGameRepo.GetMasterGame(masterGameID);
    }

    public Task<MasterGameYear?> GetMasterGameYear(Guid masterGameID, int year)
    {
        return _masterGameRepo.GetMasterGameYear(masterGameID, year);
    }

    public Task<IReadOnlyList<Guid>> GetAllSelectedMasterGameIDsForYear(int year)
    {
        return _masterGameRepo.GetAllSelectedMasterGameIDsForYear(year);
    }

    public Task UpdateCriticStats(MasterGame masterGame, OpenCriticGame openCriticGame)
    {
        return _masterGameRepo.UpdateCriticStats(masterGame, openCriticGame);
    }

    public Task UpdateCriticStats(MasterSubGame masterSubGame, OpenCriticGame openCriticGame)
    {
        return _masterGameRepo.UpdateCriticStats(masterSubGame, openCriticGame);
    }

    public Task UpdateGGStats(MasterGame masterGame, GGGame ggGame)
    {
        return _masterGameRepo.UpdateGGStats(masterGame, ggGame);
    }

    public Task SetActionProcessingMode(bool modeOn)
    {
        return _fantasyCriticRepo.SetActionProcessingMode(modeOn);
    }

    public Task CreateMasterGameRequest(MasterGameRequest domainRequest)
    {
        return _masterGameRepo.CreateMasterGameRequest(domainRequest);
    }

    public Task CreateMasterGameChangeRequest(MasterGameChangeRequest domainRequest)
    {
        return _masterGameRepo.CreateMasterGameChangeRequest(domainRequest);
    }

    public Task<IReadOnlyList<MasterGameRequest>> GetAllMasterGameRequests()
    {
        return _masterGameRepo.GetAllMasterGameRequests();
    }

    public Task<IReadOnlyList<MasterGameChangeRequest>> GetAllMasterGameChangeRequests()
    {
        return _masterGameRepo.GetAllMasterGameChangeRequests();
    }

    public Task<int> GetNumberOutstandingCorrections(MasterGame masterGame)
    {
        return _masterGameRepo.GetNumberOutstandingCorrections(masterGame);
    }

    public Task<IReadOnlyList<MasterGameRequest>> GetMasterGameRequestsForUser(FantasyCriticUser user)
    {
        return _masterGameRepo.GetMasterGameRequestsForUser(user);
    }

    public Task<IReadOnlyList<MasterGameChangeRequest>> GetMasterGameChangeRequestsForUser(FantasyCriticUser user)
    {
        return _masterGameRepo.GetMasterGameChangeRequestsForUser(user);
    }

    public Task<MasterGameRequest?> GetMasterGameRequest(Guid requestID)
    {
        return _masterGameRepo.GetMasterGameRequest(requestID);
    }

    public Task<MasterGameChangeRequest?> GetMasterGameChangeRequest(Guid requestID)
    {
        return _masterGameRepo.GetMasterGameChangeRequest(requestID);
    }

    public Task DeleteMasterGameRequest(MasterGameRequest request)
    {
        return _masterGameRepo.DeleteMasterGameRequest(request);
    }

    public Task DeleteMasterGameChangeRequest(MasterGameChangeRequest request)
    {
        return _masterGameRepo.DeleteMasterGameChangeRequest(request);
    }

    public Task CompleteMasterGameRequest(MasterGameRequest masterGameRequest, Instant responseTime,
        string responseNote, MasterGame? masterGame)
    {
        return _masterGameRepo.CompleteMasterGameRequest(masterGameRequest, responseTime, responseNote, masterGame);
    }

    public Task CompleteMasterGameChangeRequest(MasterGameChangeRequest masterGameRequest, Instant responseTime,
        string responseNote)
    {
        return _masterGameRepo.CompleteMasterGameChangeRequest(masterGameRequest, responseTime, responseNote);
    }

    public Task DismissMasterGameRequest(MasterGameRequest masterGameRequest)
    {
        return _masterGameRepo.DismissMasterGameRequest(masterGameRequest);
    }

    public Task DismissMasterGameChangeRequest(MasterGameChangeRequest request)
    {
        return _masterGameRepo.DismissMasterGameChangeRequest(request);
    }

    public Task<IReadOnlyList<MasterGameTag>> GetMasterGameTags()
    {
        return _masterGameRepo.GetMasterGameTags();
    }

    public Task<IReadOnlyDictionary<string, MasterGameTag>> GetMasterGameTagDictionary()
    {
        return _masterGameRepo.GetMasterGameTagDictionary();
    }

    public Task FinishYear(SupportedYear supportedYear)
    {
        return _fantasyCriticRepo.FinishYear(supportedYear);
    }

    public Task<IReadOnlyList<ActionProcessingSetMetadata>> GetActionProcessingSets()
    {
        return _fantasyCriticRepo.GetActionProcessingSets();
    }
}
