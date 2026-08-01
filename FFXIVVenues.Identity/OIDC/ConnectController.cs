using FFXIVVenues.Identity.DiscordSignin;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using JsonWebKeySet = FFXIVVenues.Identity.Models.JsonWebKeySet;

namespace FFXIVVenues.Identity.OIDC;

[ApiController]
[EnableCors("AllowAll")]
[Route("[controller]")]
public class ConnectController(DiscordManager discordManager, ClientManager clientManager, IConfigurationRoot config) : ControllerBase
{
    
    [HttpGet("/.well-known/openid-configuration")]
    public ActionResult<DiscoveryObject> Discovery() =>
        new DiscoveryObject($"{Request.Scheme}://{Request.Host}");

    [HttpPost("/connect/token")]
    [ResponseCache(NoStore = true)]
    public async Task<ActionResult<TokenResponse>> Token(
        [FromForm(Name = "code")] string? code,
        [FromForm(Name = "refresh_token")] string? refreshToken,
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "client_secret")] string? clientSecret,
        [FromForm(Name = "redirect_uri")] string? redirectUri,
        [FromForm(Name = "grant_type")] string grantType)
    {

        var authHeader = Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var encoded = authHeader["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var split = decoded.IndexOf(':');
            if (split > 0)
            {
                clientId = Uri.UnescapeDataString(decoded[..split]);
                clientSecret = Uri.UnescapeDataString(decoded[(split + 1)..]);
            }
        }

        if (grantType == "authorization_code")
            return await this.AuthorizationCode(code!, clientId!, clientSecret!, redirectUri!);
        else if (grantType == "refresh_token")
            return await this.RefreshToken(refreshToken, clientId, clientSecret);
        else
            return BadRequest("Grant type is invalid");
    }

    private async Task<ActionResult<TokenResponse>> AuthorizationCode(string code, string clientId, string clientSecret, string redirectUri)
    {
        if (string.IsNullOrWhiteSpace(code))
            return Unauthorized("Authorization code is invalid");
        
        var authCode = clientManager.ResolveAuthorizationCode(code);
        if (authCode is null || authCode.Expiry < DateTimeOffset.Now)
            return Unauthorized("Authorization code is invalid");

        if (clientId is null)
            return Unauthorized("Client ID is invalid");

        if (clientId != authCode.ClientId)
            return Unauthorized("Client ID is invalid");
        
        var client = clientManager.GetClient(authCode.ClientId);
        if (client is null)
            return Unauthorized("Client ID is invalid");

        if (clientSecret != client.ClientSecret)
            return Unauthorized("Client secret is invalid");
        
        if (authCode.RedirectUri != redirectUri)
            return Unauthorized("Redirect URI is invalid");

        var accessToken = await clientManager.CreateAccessTokenAsync(client.ClientId, authCode.UserId, authCode.Scopes);
        var claims = await discordManager.GetAllClaimsAsync(authCode.UserId);
        claims = clientManager.FilterClaimsToScopes(authCode.Scopes, claims);
        var idToken = clientManager.GenerateIdToken(client.ClientId, claims, $"{Request.Scheme}://{Request.Host}", authCode.Nonce);
        return new TokenResponse(idToken, accessToken.AccessToken, accessToken.RefreshToken, (int) (accessToken.Expiry - DateTimeOffset.UtcNow).TotalSeconds);
    }

    private async Task<ActionResult<TokenResponse>> RefreshToken(string? refreshToken, string? clientId, string? clientSecret)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            return Unauthorized("Refresh Token is invalid");
        
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

    [HttpGet("/connect/keys")]
    public ActionResult<JsonWebKeySet> Keys()
    {
        var publicKeyPath = config.GetValue<string>("Signing:PublicKeyPath", "config/public.pub")!;
        var publicKey = System.IO.File.ReadAllText(publicKeyPath);
        if (publicKey is null)
            return new JsonWebKeySet([]);

        var rsaProvider = RSA.Create();
        rsaProvider.ImportFromPem(publicKey);
        var keyObj = new RsaSecurityKey(rsaProvider) { KeyId = "ffxivvenues-signing-key" };

        return new JsonWebKeySet([JsonWebKeyConverter.ConvertFromRSASecurityKey(keyObj)]);
    }
    
}