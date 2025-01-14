namespace FantasyCritic.Lib.Interfaces;

public interface IHypeFactorService
{
    Task<HypeConstants> GetHypeConstants(IEnumerable<MasterGameYear> allMasterGameYears);
}
