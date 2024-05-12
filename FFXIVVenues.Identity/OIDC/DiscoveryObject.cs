using System.Text.Json.Serialization;

namespace FFXIVVenues.Identity.OIDC;

public class DiscoveryObject(string rootUri)
{
    [JsonPropertyName("issuer")] 
    public string Issuer { get; set; } = $"{rootUri}";

    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; set; } = $"https://{rootUri}/connect/authorize";

    [JsonPropertyName("token_endpoint")] 
    public string TokenEndpoint { get; set; } = $"https://{rootUri}/connect/token";

    [JsonPropertyName("userinfo_endpoint")]
    public string UserInfoEndpoint { get; set; } = $"https://{rootUri}/@me";

    [JsonPropertyName("revocation_endpoint")]
    public string RevocationEndpoint { get; set; } = $"https://{rootUri}/connect/revoke";

    [JsonPropertyName("jwks_uri")] 
    public string? JwksUri { get; set; } = $"https://{rootUri}/connect/keys";

    public static string[] ResponseTypesSupportedStatic = [ "code", /*"token", "id_token" */];
    [JsonPropertyName("response_types_supported")]
    public string[] ResponseTypesSupported { get; set; } = DiscoveryObject.ResponseTypesSupportedStatic;

    [JsonPropertyName("subject_types_supported")]
    public string[] SubjectTypesSupported { get; set; } = [ "public" ];

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public string[] IdTokenSigningAlgValuesSupported { get; set; } = ["RS256"];

    [JsonPropertyName("scopes_supported")]
    public string[] ScopesSupported { get; set; } =
    [
        "openid",
        "profile",
        "email", 
        "roles"
    ];

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public string[] TokenEndpointAuthMethodsSupported { get; set; } =
    [
        "client_secret_basic",
        "client_secret_post"
    ];

    [JsonPropertyName("claims_supported")]
    public string[] ClaimsSupported { get; set; } =
    [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "name",
        "nickname",
        "preferred_username",
        "email",
        "email_verified",
        "profile",
        "picture"
    ];
}