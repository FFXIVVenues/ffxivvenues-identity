namespace FFXIVVenues.Identity.Connect.Clients;

public record AuthorizationCode(string Code, string ClientId, string UserId, DateTimeOffset Expiry);