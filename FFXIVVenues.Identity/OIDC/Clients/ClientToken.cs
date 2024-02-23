namespace FFXIVVenues.Identity.OIDC.Clients;

public record ClientToken(string ClientId, string UserId, string[] Scopes, TokenResponse Token);