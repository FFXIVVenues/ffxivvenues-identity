namespace FFXIVVenues.Identity.OIDC.Clients;

public class Client
{
    public required string ClientName { get; init; }
    public required string ClientDescription { get; init; }
    public required string ClientIcon { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required ClientScope[] Scopes { get; init; }
    public required string[] RedirectUris { get; init; }
    public required AccessControl AccessControl { get; init; }
}

public class AccessControl
{
    public bool DefaultAccess { get; set; }
    public AllowFromGuilds[] AllowFromGuilds { get; set; }
    public long[] AllowFromIds { get; set; }
    public long[] DenyFromIds { get; set; }
}

public class AllowFromGuilds
{
    public long GuildId { get; set; }
    public long[] AnyOfRoles { get; set; }
    public long[] AllOfRoles { get; set; }
}

public record ClientScope(string Name, string Justification);
