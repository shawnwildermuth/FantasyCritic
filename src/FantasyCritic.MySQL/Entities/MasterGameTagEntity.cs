using System.Runtime.CompilerServices;
using Newtonsoft.Json;

[assembly: InternalsVisibleTo("FantasyCritic.BetaSync")]
namespace FantasyCritic.MySQL.Entities;

internal class MasterGameTagEntity
{
    public MasterGameTagEntity()
    {

    }

    public MasterGameTagEntity(MasterGameTag domain)
    {
        Name = domain.Name;
        ReadableName = domain.ReadableName;
        ShortName = domain.ShortName;
        TagType = domain.TagType.Name;
        HasCustomCode = domain.HasCustomCode;
        SystemTagOnly = domain.SystemTagOnly;
        Description = domain.Description;
        Examples = JsonConvert.SerializeObject(domain.Examples);
        BadgeColor = domain.BadgeColor;
    }

    public string Name { get; set; } = null!;
    public string ReadableName { get; set; } = null!;
    public string ShortName { get; set; } = null!;
    public string TagType { get; set; } = null!;
    public bool HasCustomCode { get; set; }
    public bool SystemTagOnly { get; set; }
    public string Description { get; set; } = null!;
    public string Examples { get; set; } = null!;
    public string BadgeColor { get; set; } = null!;

    public MasterGameTag ToDomain()
    {
        var examples = JsonConvert.DeserializeObject<List<string>>(Examples)!;
        return new MasterGameTag(Name, ReadableName, ShortName, new MasterGameTagType(TagType), HasCustomCode, SystemTagOnly, Description, examples, BadgeColor);
    }
}
