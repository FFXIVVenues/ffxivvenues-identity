namespace FFXIVVenues.Identity.OIDC;

public record AuthorizationCode(string Code, string ClientId, long UserId, DateTimeOffset Expiry, string RedirectUri, string[] Scopes);