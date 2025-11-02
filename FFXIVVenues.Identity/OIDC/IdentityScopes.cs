namespace FFXIVVenues.Identity.OIDC;

public static class IdentityScopes
{
    public const string OpenId = "openid";
    public const string Profile = "profile";
    public const string Email = "email";
    public const string EmailVerification = "email_verification";
    public const string MfaStatus = "mfa_status";
    public const string Roles = "roles";
    
    public static string[] GetAllowedClaims(string[] scopes)
    {
        var allowedClaims = new List<string>()
        {
            ConnectClaims.Iss,
            ConnectClaims.Aud,
            ConnectClaims.Exp,
            ConnectClaims.Iat,
        };
        foreach (var scope in scopes)
            allowedClaims.AddRange(GetAllowedClaimsForScope(scope));
        return allowedClaims.Distinct().ToArray();
    }

    public static string[] GetAllowedClaimsForScope(string scope) =>
        scope switch
        {
            OpenId =>  [ ConnectClaims.Sub ],
            Profile=>  [ConnectClaims.Name, ConnectClaims.Nickname, ConnectClaims.PreferredUsername, ConnectClaims.Picture, ConnectClaims.Profile ],
            Email => [ ConnectClaims.Email, ConnectClaims.EmailVerified ],
            EmailVerification => [ ConnectClaims.EmailVerified ],
            MfaStatus => [ ConnectClaims.MfaEnabled ],
            Roles => [],
            _ => []
        };

}