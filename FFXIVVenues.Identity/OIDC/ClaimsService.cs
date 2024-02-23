using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace FFXIVVenues.Identity.OIDC;

public class ClaimsService(IHttpContextAccessor httpContextAccessor, IConfiguration config)
{

    public IIdentity? GetIdentity()
    {
        if (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated != true)
            return null;
        return httpContextAccessor.HttpContext.User.Identity;
    }

    public Claim? GetClaim(string claimType)
    {
        if (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated != true)
            return null;
        return httpContextAccessor.HttpContext?.User.Claims
            .FirstOrDefault(c => c.Type == claimType);
    }
    
    public string? GetClaimValue(string claimType, string? @default = null)
    {
        var claim = this.GetClaim(claimType);
        return claim == null ? @default : claim.Value;
    }

    public string GenerateIdToken(string clientId, string clientSecret)
    {
        var symmetricKeyBytes = Encoding.UTF8.GetBytes(clientSecret);
        var keyObj = new SymmetricSecurityKey(symmetricKeyBytes);

        const string issuer = "id.ffxivvenues.com";
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(180);

        var claims = new List<Claim?>
        {
            this.GetClaim(ConnectClaims.Sub),
            this.GetClaim(ConnectClaims.Name),
            this.GetClaim(ConnectClaims.Nickname),
            this.GetClaim(ConnectClaims.PreferredUsername),
            this.GetClaim(ConnectClaims.Email),
            this.GetClaim(ConnectClaims.EmailVerified),
            this.GetClaim(ConnectClaims.Picture),
            new Claim(ConnectClaims.Profile, 
                $"https://{httpContextAccessor.HttpContext?.Request.Host}/profile")
        };
        claims.RemoveAll(c => c is null);

        var payload = new JwtPayload(issuer, clientId, claims, now, expires, now);
        var header = new JwtHeader(new SigningCredentials(keyObj, SecurityAlgorithms.HmacSha256));
        var token = new JwtSecurityToken(header, payload);
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(token);
    }
    
}