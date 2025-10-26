using System.ComponentModel.DataAnnotations;

namespace FFXIVVenues.Identity.Models;

public class DiscordToken
{
    [Key] public required long UserId { get; init; }
    [MaxLength(4096)] public required string AccessToken { get; set; }
    [MaxLength(4096)] public required string RefreshToken { get; set; }
    public required DateTimeOffset Expiry { get; set; }
}
