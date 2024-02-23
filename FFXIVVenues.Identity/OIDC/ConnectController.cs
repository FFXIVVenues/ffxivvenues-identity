using FFXIVVenues.Identity.OIDC.Clients;
using Microsoft.AspNetCore.Mvc;

namespace FFXIVVenues.Identity.OIDC;

[ApiController]
[Route("[controller]")]
public class ConnectController(ClientManager _clientManager) : ControllerBase
{
    
    [HttpGet("/.well-known/openid-configuration")]
    public ActionResult<DiscoveryObject> Discovery() =>
        new DiscoveryObject(this.HttpContext.Request.Host.ToString());

    [HttpPost("/connect/token")]
    [ResponseCache(NoStore = true)]
    public ActionResult<TokenResponse> Token(
        [FromForm(Name = "code")] string code,
        [FromForm(Name = "client_id")] string clientId,
        [FromForm(Name = "client_secret")] string clientSecret,
        [FromForm(Name = "redirect_uri")] string redirectUri,
        [FromForm(Name = "grant_type")] string grantType)
    {
        var authCode = _clientManager.ResolveAuthorizationCode(code);
        if (authCode is null || authCode.Expiry < DateTimeOffset.Now)
            return BadRequest("Authorization code is invalid");

        if (authCode.ClientId != clientId)
            return BadRequest("Client ID is invalid");
        
        var client = _clientManager.GetClient(clientId);
        if (client is null)
            return BadRequest("Client ID is invalid");

        if (client.ClientSecret != clientSecret)
            return BadRequest("Client secret is invalid");
        
        if (! client.RedirectUris.Contains(redirectUri))
            return BadRequest("Redirect URI is invalid");
            
        if (grantType != "authorization_code")
            return BadRequest("Grant type is invalid");

        return _clientManager.CreateTokenResponse(clientId, clientSecret, authCode.UserId, authCode.Scopes);
    }
        
}