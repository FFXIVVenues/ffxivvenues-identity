using System.Collections.Concurrent;
using FFXIVVenues.Identity.Helpers;

namespace FFXIVVenues.Identity.OIDC.Clients;

public class ClientManager
{
    private readonly ClaimsService _claimsService;
    private static readonly TimeSpan AuthCodeExpiry = TimeSpan.FromSeconds(15);
    
    private readonly Client[] _clients;
    private readonly ConcurrentDictionary<string, AuthorizationCode> _authStore = new();
    private readonly ConcurrentDictionary<string, ClientToken> _tokenStore = new();

    public ClientManager(IConfigurationRoot config, ClaimsService claimsService)
    {
        _claimsService = claimsService;
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

    public TokenResponse CreateTokenResponse(string clientId, string clientSecret, string userId, string[] scopes)
    {
        var idToken = this._claimsService.GenerateIdToken(clientId, clientSecret);
        var token = new TokenResponse(idToken, IdHelper.GenerateId(32), IdHelper.GenerateId(32), 3600);
        _tokenStore.TryAdd(token.AccessToken, new ClientToken(clientId, userId, scopes, token));
        return token;
    }
    
}