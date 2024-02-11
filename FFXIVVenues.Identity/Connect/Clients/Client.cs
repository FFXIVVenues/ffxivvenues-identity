namespace FFXIVVenues.Identity.Connect.Clients;

public record Client(string ClientName, string ClientId, string ClientSecret, string[] Scopes);
