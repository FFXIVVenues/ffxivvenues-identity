using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace FFXIVVenues.Identity.OIDC;

/// <summary>
/// Provides methods for working with the Browser Session's
/// Claims Identity. Not to be confused with Claims provided
/// via the IdToken in Service to Service calls. 
/// </summary>
/// <param name="httpContextAccessor"></param>
public class SessionIdentityManager(IHttpContextAccessor httpContextAccessor)
{

    public IIdentity? GetIdentity()
    {
        if (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated != true)
            return null;
        return httpContextAccessor.HttpContext.User.Identity;
    }

    public async Task Logout()
    {
        if (httpContextAccessor.HttpContext is not null)
            await httpContextAccessor.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
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

    public Claim[]? GetAllClaims()
    {
        if (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated != true)
            return null;
        
        return httpContextAccessor.HttpContext?.User.Claims.ToArray();
    }
    
}