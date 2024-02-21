using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text;
using FFXIVVenues.Identity.Helpers;

namespace FFXIVVenues.Identity.Connect.Clients;

public class ClientManager
{
    private static readonly TimeSpan AuthCodeExpiry = TimeSpan.FromSeconds(5);
    
    private readonly Client[] _clients;
    private readonly ConcurrentDictionary<string, AuthorizationCode> _authStore = new();
    private readonly ConcurrentDictionary<string, ClientToken> _tokenStore = new();

    public ClientManager(IConfigurationRoot config)
    {
        _clients = config.GetSection("Clients").GetChildren().Select(x => x.Get<Client>()).ToArray();
    }

    public Client? GetClient(string clientId) =>
        this._clients.FirstOrDefault(c => c.ClientId == clientId);

    public AuthorizationCode CreateAuthorizationCode(string clientId, string userId, string redirectUri, IEnumerable<ClientScope> scopes)
    {
        var authCode = new AuthorizationCode(IdHelper.GenerateId(32), clientId, userId,
            DateTimeOffset.Now + AuthCodeExpiry, redirectUri, scopes.Select(s => s.Name).ToArray());
        this._authStore.TryAdd(authCode.Code, authCode);
        Task.Delay(AuthCodeExpiry).ContinueWith(_ => this._authStore.TryRemove(authCode.Code, out var _));
        return authCode;
    }

    public AuthorizationCode? ResolveAuthorizationCode(string code) =>
        this._authStore.TryRemove(code, out var authCode) ? authCode : null;

    public TokenResponse CreateTokenResponse(string clientId, string userId, string[] scopes)
    {
        var token = new TokenResponse(IdHelper.GenerateId(32), IdHelper.GenerateId(32), IdHelper.GenerateId(32), 3600);
        _tokenStore.TryAdd(token.AccessToken, new ClientToken(clientId, userId, scopes, token));
        return token;
    }
    
    // public string GenerateJwtToken(string username)
    // {
    //     var claims = new[]
    //     {
    //         new Claim(JwtRegisteredClaimNames.Sub, username),
    //         new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    //         // Add other claims as needed.
    //     };
    //
    //     var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your_secret_key_here"));
    //     var creds = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
    //
    //     var token = new JwtSecurityToken(
    //         issuer: "your_auth_server",
    //         audience: "your_client_id",
    //         claims: claims,
    //         expires: DateTime.Now.AddMinutes(30),
    //         signingCredentials: creds);
    //
    //     return new JwtSecurityTokenHandler().WriteToken(token);
    // }
    
}