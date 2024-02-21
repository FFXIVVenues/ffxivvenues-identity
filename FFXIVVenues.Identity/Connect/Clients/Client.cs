namespace FFXIVVenues.Identity.Connect.Clients;

public class Client
{
    public required string ClientName { get; init; }
    public required string ClientDescription { get; init; }
    public required string ClientIcon { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required ClientScope[] Scopes { get; init; }
    public required string[] RedirectUris { get; init; }
}

public record ClientScope(string Name, string Justification);
