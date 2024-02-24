using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json.Nodes;
using FFXIVVenues.Identity.DiscordSignin;
using Microsoft.AspNetCore.Mvc;

namespace FFXIVVenues.Identity.OIDC;

public class UserController(
    ClaimsIdentityManager claimsIdentityManager,
    ClientManager clientManager,
    DiscordManager discordManager) : ControllerBase
{

    [HttpGet("/@me")]
    [HttpPost("/@me")]
    public async Task<ActionResult<JsonObject>> Me()
    {
        var claims = claimsIdentityManager.GetAllClaims();
        if (claims is not null)
            return this.ClaimsToObject(claims);
        
        var accessToken = this.HttpContext.Request.Headers.Authorization
            .Select(a => AuthenticationHeaderValue.TryParse(a, out var val) ? val : null)
            .FirstOrDefault(a => a?.Scheme == "Bearer")?.Parameter;

        if (accessToken is null)
            return Unauthorized();
        
        var verifiedToken = await clientManager.GetAccessTokenAsync(accessToken);
        if (verifiedToken is null || verifiedToken.Expiry > DateTimeOffset.UtcNow)
            return Unauthorized();

        claims = await discordManager.GetAllClaimsAsync(verifiedToken.UserId);
        return this.ClaimsToObject(claims);
    }

    private ActionResult<JsonObject> ClaimsToObject(Claim[] claims)
    {
        var json = new JsonObject();
        foreach (var claim in claims)
            json.Add(claim.Type, claim.Value);
        return json;
    }
        
}
