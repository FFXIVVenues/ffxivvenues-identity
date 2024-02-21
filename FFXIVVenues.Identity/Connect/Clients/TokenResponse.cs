using System.Text.Json.Serialization;

namespace FFXIVVenues.Identity.Connect.Clients;

public record TokenResponse(
    [property: JsonPropertyName("id_token")] string IdToken,
    [property: JsonPropertyName("access_token")] string AccessToken, 
    [property: JsonPropertyName("refresh_token")] string RefreshToken, 
    [property: JsonPropertyName("expires_in")] int ExpiresIn)
{
    public string TokenType => "Bearer";
}
