using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace FFXIVVenues.Identity.Models;

[Index(nameof(RefreshToken))]
[Index(nameof(ClientId))]
public class ClientToken
{
    [Key] [MaxLength(32)] public required string AccessToken { get; init; }
    public required string[] Scopes { get; init; } 
    public required long UserId { get; init; }
    [MaxLength(32)] public required string RefreshToken { get; init; }
    [MaxLength(16)] public required string ClientId { get; init; } 
    public required DateTimeOffset Expiry { get; init; }
}
