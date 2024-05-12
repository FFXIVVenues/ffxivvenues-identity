using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FFXIVVenues.Identity.DiscordSignin;
using FFXIVVenues.Identity.Helpers;
using FFXIVVenues.Identity.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;

namespace FFXIVVenues.Identity.OIDC;

public class ClientManager(IConfigurationRoot config, DiscordManager discordManager, IdentityDbContext db)
{
    private static readonly TimeSpan AuthCodeExpiry = TimeSpan.FromSeconds(15);

    private static Dictionary<string, string[]> ScopeClaimMap = new()
    {
        { "openid", [ ConnectClaims.Sub, ConnectClaims.Iss, ConnectClaims.Aud, ConnectClaims.Exp, ConnectClaims.Iat ] },
        { "profile", [ ConnectClaims.Name, ConnectClaims.PreferredUsername, ConnectClaims.Nickname, ConnectClaims.Picture, ConnectClaims.Profile, ConnectClaims.MfaEnabled ] },
        { "email", [ ConnectClaims.Email, ConnectClaims.EmailVerified ] },
        { "roles", [] },
    };
    
    private readonly Client[] _clients = config.GetSection("Clients").GetChildren().Select(x => x.Get<Client>()!).ToArray();
    private readonly ConcurrentDictionary<string, AuthorizationCode> _authStore = new();

    public Client? GetClient(string clientId) =>
        this._clients.FirstOrDefault(c => c.ClientId == clientId);

    public AuthorizationCode CreateAuthorizationCode(string clientId, long userId, string redirectUri, IEnumerable<ClientScope> scopes)
    {
        var authCode = new AuthorizationCode(IdHelper.GenerateId(32), clientId, userId,
            DateTimeOffset.Now + AuthCodeExpiry, redirectUri, scopes.Select(s => s.Name).ToArray());
        this._authStore.TryAdd(authCode.Code, authCode);
        Task.Delay(AuthCodeExpiry).ContinueWith(_ => this._authStore.TryRemove(authCode.Code, out var _));
        return authCode;
    }

    public AuthorizationCode? ResolveAuthorizationCode(string code) =>
        this._authStore.TryRemove(code, out var authCode) ? authCode : null;

    public string GenerateIdToken(string clientId, Claim[] claims)
    {
        var key = config.GetValue<string>("Signing:Private");
        var rsaProvider = new RSACryptoServiceProvider();
        rsaProvider.ImportFromPem(key);

        var keyObj = new RsaSecurityKey(rsaProvider);

        const string issuer = "id.ffxivvenues.com";
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(180);

        var payload = new JwtPayload(issuer, clientId, claims, now, expires, now);

        // Use RSA SHA256 for signing credentials
        var header = new JwtHeader(new SigningCredentials(keyObj, SecurityAlgorithms.RsaSha256));
        var idToken = new JwtSecurityToken(header, payload);

        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(idToken);
    }
    
    public Claim[] FilterClaimsToScopes(string[] scopes, Claim[] claims)
    {
        var allowedClaims = ScopeClaimMap.Where(k => scopes.Contains(k.Key)).SelectMany(k => k.Value);
        return claims.Where(c => allowedClaims.Contains(c.Type)).ToArray();
    }
    
    public async Task<ClientToken> CreateAccessTokenAsync(string clientId, long userId, string[] scopes)
    {
        var token = new ClientToken
        {
            ClientId = clientId,
            AccessToken = IdHelper.GenerateId(32),
            RefreshToken = IdHelper.GenerateId(32),
            UserId = userId,
            Scopes = scopes,
            Expiry = DateTimeOffset.UtcNow.AddHours(1)
        };
        await db.ClientTokens.AddAsync(token);
        await db.SaveChangesAsync();
        return token;
    }

    public Task<ClientToken?> GetAccessTokenByRefreshAsync(string refreshToken) =>
        db.ClientTokens.FirstOrDefaultAsync(t => t.RefreshToken == refreshToken);
    
    public ValueTask<ClientToken?> GetAccessTokenAsync(string accessToken) =>
        db.ClientTokens.FindAsync(accessToken);

    public async Task<ClientToken> RefreshAccessTokenAsync(ClientToken token)
    {
        db.ClientTokens.Remove(token);

        var newToken = new ClientToken
        {
            ClientId = token.ClientId,
            AccessToken = IdHelper.GenerateId(32),
            RefreshToken = IdHelper.GenerateId(32),
            UserId = token.UserId,
            Scopes = token.Scopes,
            Expiry = DateTimeOffset.UtcNow.AddHours(1)
        };
        await db.ClientTokens.AddAsync(newToken);
        await db.SaveChangesAsync();
        return newToken;
    }

    public async Task RevokeAccessTokenAsync(string clientId, long userId)
    {
        var tokens = db.ClientTokens.Where(t => t.ClientId == clientId && t.UserId == userId);
        foreach (var token in tokens)
            db.ClientTokens.Remove(token);
        await db.SaveChangesAsync();
    }

    public async Task<bool> CanAccessClientAsync(string clientId, long userId)
    {
        var client = this.GetClient(clientId);
        if (client is null)
            return false;
        
        if (client.AccessControl is null)
            return true;

        if (client.AccessControl.DenyFromIds.Contains(userId))
            return false;

        if (client.AccessControl.DefaultAccess)
            return true;
        
        if (client.AccessControl.AllowFromIds.Contains(userId))
            return true;

        try
        {
            var guilds = await discordManager.GetGuildsForUserAsync(userId);
            foreach (var guild in client.AccessControl.AllowFromGuilds)
            {
                if (!guilds.Contains(guild.GuildId))
                    continue;

                var hasRequiredRoles = guild.AllOfRoles is { Length: > 0 };
                var hasSingularRoles = guild.AnyOfRoles is { Length: > 0 };
                if (!hasRequiredRoles && !hasSingularRoles)
                    return true;

                var usersRoles = await discordManager.GetRolesForUserInGuildAsync(userId, guild.GuildId);
                var hasAllRequiredRoles = !hasRequiredRoles || guild.AllOfRoles.All(role => usersRoles.Contains(role));
                var hasAnySingleRole = !hasSingularRoles || guild.AnyOfRoles.Any(role => usersRoles.Contains(role));

                if (hasAllRequiredRoles is false)
                    continue;

                if (hasAnySingleRole is false)
                    continue;

                return true;
            }
        }
        catch (Exception e)
        {
            Log.Error(e, "Could not query roles for user");
            return false;
        }

        return client.AccessControl.DefaultAccess;
    }
}