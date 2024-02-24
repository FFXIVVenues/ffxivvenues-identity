﻿using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FFXIVVenues.Identity.Helpers;
using FFXIVVenues.Identity.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace FFXIVVenues.Identity.OIDC;

public class ClientManager(IConfigurationRoot config, IHttpContextAccessor httpContextAccessor, ClaimsIdentityManager claimsIdentityManager, IdentityDbContext db)
{
    private static readonly TimeSpan AuthCodeExpiry = TimeSpan.FromSeconds(15);
    
    private readonly Client[] _clients = config.GetSection("Clients").GetChildren().Select(x => x.Get<Client>()).ToArray();
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
    
    public string GenerateIdToken(string clientId, string clientSecret)
    {
        var symmetricKeyBytes = Encoding.UTF8.GetBytes(clientSecret);
        var keyObj = new SymmetricSecurityKey(symmetricKeyBytes);

        const string issuer = "id.ffxivvenues.com";
        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(180);

        var claims = new List<Claim?>
        {
            claimsIdentityManager.GetClaim(ConnectClaims.Sub),
            claimsIdentityManager.GetClaim(ConnectClaims.Name),
            claimsIdentityManager.GetClaim(ConnectClaims.Nickname),
            claimsIdentityManager.GetClaim(ConnectClaims.PreferredUsername),
            claimsIdentityManager.GetClaim(ConnectClaims.Email),
            claimsIdentityManager.GetClaim(ConnectClaims.EmailVerified),
            claimsIdentityManager.GetClaim(ConnectClaims.MfaEnabled),
            claimsIdentityManager.GetClaim(ConnectClaims.Picture),
            new Claim(ConnectClaims.Profile, 
                $"https://{httpContextAccessor.HttpContext?.Request.Host}/profile")
        };
        claims.RemoveAll(c => c is null);

        var payload = new JwtPayload(issuer, clientId, claims, now, expires, now);
        var header = new JwtHeader(new SigningCredentials(keyObj, SecurityAlgorithms.HmacSha256));
        var token = new JwtSecurityToken(header, payload);
        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(token);
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
}