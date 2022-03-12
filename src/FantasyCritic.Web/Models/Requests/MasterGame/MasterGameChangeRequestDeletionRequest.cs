using System.ComponentModel.DataAnnotations;

namespace FantasyCritic.Web.Models.Requests.MasterGame;

public class MasterGameChangeRequestDeletionRequest
{
    [Required]
    public Guid RequestID { get; set; }
}
