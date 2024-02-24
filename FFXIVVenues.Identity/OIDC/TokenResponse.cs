using System.Text.Json.Serialization;

namespace FFXIVVenues.Identity.OIDC;

public record TokenResponse(
    [property: JsonPropertyName("id_token")] [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? IdToken,
    [property: JsonPropertyName("access_token")] string AccessToken, 
    [property: JsonPropertyName("refresh_token")] string RefreshToken, 
    [property: JsonPropertyName("expires_in")] int ExpiresIn)
{
    [property: JsonPropertyName("token_type")] public string TokenType => "Bearer";
}
