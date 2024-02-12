using System.Collections.Concurrent;
using FFXIVVenues.Identity.Helpers;

namespace FFXIVVenues.Identity.Connect.Clients;

public class ClientManager(IConfigurationRoot config)
{
    private static readonly TimeSpan AuthCodeExpiry = TimeSpan.FromSeconds(5);
    
    private readonly Client[] _clients = 
        config.GetSection("Clients").Get<Client[]>() ?? Array.Empty<Client>();
    private readonly ConcurrentDictionary<string, AuthorizationCode> _authStore = new();

    public Client? GetClient(string clientId) =>
        this._clients.FirstOrDefault(c => c.ClientId == clientId);

    public AuthorizationCode GetAuthorizationCode(string clientId, string userId)
    {
        var authCode = new AuthorizationCode(IdHelper.GenerateId(32), clientId, userId,
            DateTimeOffset.Now + AuthCodeExpiry);
        this._authStore.TryAdd(authCode.Code, authCode);
        Task.Delay(AuthCodeExpiry).ContinueWith(_ => this._authStore.TryRemove(authCode.Code, out var _));
        return authCode;
    }

    public AuthorizationCode? ResolveAuthorizationCode(string code) =>
        this._authStore.TryRemove(code, out var authCode) ? authCode : null;
}