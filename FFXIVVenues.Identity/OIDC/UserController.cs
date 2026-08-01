using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json.Nodes;
using FFXIVVenues.Identity.DiscordSignin;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace FFXIVVenues.Identity.OIDC;

[ApiController]
[EnableCors("AllowAll")]
[Route("[controller]")]
public class UserController(
    SessionIdentityManager sessionIdentityManager,
    ClientManager clientManager,
    DiscordManager discordManager) : ControllerBase
{

    [HttpGet("/@me")]
    [HttpPost("/@me")]
    public async Task<ActionResult<JsonObject>> Me()
    {
        IEnumerable<Claim> claims = sessionIdentityManager.GetAllClaims();
        if (claims is not null)
            return ClaimsToObject(claims);
        
        var accessToken = this.HttpContext.Request.Headers.Authorization
            .Select(a => AuthenticationHeaderValue.TryParse(a, out var val) ? val : null)
            .FirstOrDefault(a => a?.Scheme == "Bearer")?.Parameter;

        if (accessToken is null)
            return Unauthorized();
        
        var verifiedToken = await clientManager.GetClientTokenAsync(accessToken);
        if (verifiedToken is null || verifiedToken.Expiry < DateTimeOffset.UtcNow)
            return Unauthorized();

        claims = await discordManager.GetAllClaimsAsync(verifiedToken.UserId);
        claims = claims.FilterToScopes(verifiedToken.Scopes);
        
        return ClaimsToObject(claims);
    }
    
    private static ActionResult<JsonObject> ClaimsToObject(IEnumerable<Claim> claims)
    {
        var json = new JsonObject();
        foreach (var claim in claims)
            json.Add(claim.Type, claim.Value);
        return json;
    }

}
