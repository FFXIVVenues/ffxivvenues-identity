using Microsoft.AspNetCore.Mvc;

namespace FFXIVVenues.Identity.OIDC;

[ApiController]
[Route("[controller]")]
public class ConnectController(ClientManager clientManager) : ControllerBase
{
    
    [HttpGet("/.well-known/openid-configuration")]
    public ActionResult<DiscoveryObject> Discovery() =>
        new DiscoveryObject(this.HttpContext.Request.Host.ToString());

    [HttpPost("/connect/token")]
    [ResponseCache(NoStore = true)]
    public async Task<ActionResult<TokenResponse>> Token(
        [FromForm(Name = "code")] string? code,
        [FromForm(Name = "refresh_token")] string? refreshToken,
        [FromForm(Name = "client_id")] string clientId,
        [FromForm(Name = "client_secret")] string clientSecret,
        [FromForm(Name = "redirect_uri")] string? redirectUri,
        [FromForm(Name = "grant_type")] string grantType)
    {
        if (grantType == "authorization_code")
            return await this.AuthorizationCode(code!, clientId, clientId, redirectUri!);
        else if (grantType == "refresh_token")
            return await this.RefreshToken(refreshToken, clientId, clientId);
        else
            return BadRequest("Grant type is invalid");
    }

    private async Task<ActionResult<TokenResponse>> AuthorizationCode(string code, string clientId, string clientSecret, string redirectUri)
    {
        var authCode = clientManager.ResolveAuthorizationCode(code);
        if (authCode is null || authCode.Expiry < DateTimeOffset.Now)
            return Unauthorized("Authorization code is invalid");

        if (authCode.ClientId != clientId)
            return Unauthorized("Client ID is invalid");
        
        var client = clientManager.GetClient(clientId);
        if (client is null)
            return Unauthorized("Client ID is invalid");

        if (client.ClientSecret != clientSecret)
            return Unauthorized("Client secret is invalid");
        
        if (! client.RedirectUris.Contains(redirectUri))
            return Unauthorized("Redirect URI is invalid");
        
        var idToken = clientManager.GenerateIdToken(clientId, clientSecret);
        var accessToken = await clientManager.CreateAccessTokenAsync(clientId, authCode.UserId, authCode.Scopes);
        return new TokenResponse(idToken, accessToken.AccessToken, accessToken.RefreshToken, (accessToken.Expiry - DateTimeOffset.UtcNow).Seconds);
    }

    private async Task<ActionResult<TokenResponse>> RefreshToken(string refreshToken, string clientId, string clientSecret)
    {
        var token = await clientManager.GetAccessTokenByRefreshAsync(refreshToken);
        if (token == null)
            return Unauthorized("Refresh Token is invalid");
        
        if (token.ClientId != clientId)
            return Unauthorized("Client ID is invalid");
        
        var client = clientManager.GetClient(clientId);
        if (client is null)
            return Unauthorized("Client ID is invalid");

        if (client.ClientSecret != clientSecret)
            return Unauthorized("Client secret is invalid");

        var refreshedToken = await clientManager.RefreshAccessTokenAsync(token);
        return new TokenResponse(null, refreshedToken.AccessToken, refreshedToken.RefreshToken, (refreshedToken.Expiry - DateTimeOffset.UtcNow).Seconds);
    }
    
}