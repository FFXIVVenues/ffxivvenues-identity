using System.Security.Claims;

namespace FFXIVVenues.Identity.OIDC;

public static class IdentityScopes
{
    public const string OpenId = "openid";
    public const string Profile = "profile";
    public const string Email = "email";
    public const string EmailFake = "email_fake";
    public const string EmailVerification = "email_verification";
    public const string MfaStatus = "mfa_status";
    public const string Roles = "roles";
    
    public static string[] GetAllowedClaimTypes(IEnumerable<string> scopes)
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
            Profile =>  [ConnectClaims.Name, ConnectClaims.Nickname, ConnectClaims.PreferredUsername, ConnectClaims.Picture, ConnectClaims.Profile ],
            Email => [ ConnectClaims.Email, ConnectClaims.EmailVerified ],
            EmailFake => [ ConnectClaims.EmailFake ],
            EmailVerification => [ ConnectClaims.EmailVerified ],
            MfaStatus => [ ConnectClaims.MfaEnabled ],
            Roles => [],
            _ => []
        };
    
    public static string[] GetClaimFakeTargets(string claim) =>
        claim switch
        {
            ConnectClaims.EmailFake =>  [ ConnectClaims.Email ],
            _ => []
        };

    public static Claim[] FilterToScopes(this IEnumerable<Claim> claims, IEnumerable<string> scopes)
    {
        var claimsAllowed = GetAllowedClaimTypes(scopes);
        var newClaims = claims.Where(c => claimsAllowed.Contains(c.Type)).ToList();
        // ReSharper disable PossibleMultipleEnumeration
        foreach (var newClaim in newClaims.ToList())
        foreach (var fakeTarget in GetClaimFakeTargets(newClaim.Type))
        {
            if (newClaims.All(c => c.Type != fakeTarget))
                newClaims.Add(new Claim(fakeTarget, newClaim.Value));
        }

        return newClaims.ToArray();
        // ReSharper restore PossibleMultipleEnumeration
    }
}