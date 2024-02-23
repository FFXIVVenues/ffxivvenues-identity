namespace FFXIVVenues.Identity.OIDC.Clients;

public record AuthorizationCode(string Code, string ClientId, string UserId, DateTimeOffset Expiry, string RedirectUri, string[] Scopes);