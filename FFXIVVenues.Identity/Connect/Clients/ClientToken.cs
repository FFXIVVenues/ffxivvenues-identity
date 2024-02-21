namespace FFXIVVenues.Identity.Connect.Clients;

public record ClientToken(string ClientId, string UserId, string[] Scopes, TokenResponse Token);