using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using FFXIVVenues.Identity.Models;
using FFXIVVenues.Identity.OIDC;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace FFXIVVenues.Identity.DiscordSignin;

public class DiscordManager(IConfiguration config, IdentityDbContext db, HttpClient httpClient, DiscordOptions discordOptions, IMemoryCache memoryCache)
{
    private string _discordClientId = config.GetValue<string>("Discord:ClientId");
    private string _discordClientSecret = config.GetValue<string>("Discord:ClientSecret");
    
    public async Task StoreDiscordTokensAsync(long userId, string accessToken, string refreshToken, int expiresIn)
    {
        var expiry = DateTimeOffset.UtcNow.AddSeconds(expiresIn);

        var discordToken = new DiscordToken
        {
            UserId = userId,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            Expiry = expiry
        };

        var existingKey = await db.DiscordTokens.FindAsync(userId);
        if (existingKey is not null)
            db.DiscordTokens.Remove(existingKey);
        await db.DiscordTokens.AddAsync(discordToken);
        await db.SaveChangesAsync();
    }
    
    public async Task<DiscordToken?> GetDiscordTokenAsync(long userId, bool refresh = true)
    {
        var discordToken = await db.DiscordTokens.FirstOrDefaultAsync(t => t.UserId == userId);
        if (discordToken == null)
            return null;
        if (refresh && discordToken.Expiry < DateTimeOffset.UtcNow)
            return await RefreshDiscordTokenAsync(discordToken);
        return discordToken;
    }

    private async Task<DiscordToken> RefreshDiscordTokenAsync(DiscordToken discordToken)
    {
        KeyValuePair<string, string>[] formValues = [
            new ("grant_type", "refresh_token"),
            new ("refresh_token", discordToken.RefreshToken),
            new ("client_id", _discordClientId),
            new ("refresh_token", _discordClientSecret),
        ];
        var apiResponse =
            await httpClient.PostAsync(DiscordOptions.TokenEndpointUri, new FormUrlEncodedContent(formValues));

        if ( ! apiResponse.IsSuccessStatusCode)
            throw new RefreshException("Call to refresh Discord Access Token failed");
        var tokenResponse = await apiResponse.Content.ReadFromJsonAsync<TokenResponse>();
        if (tokenResponse == null)
            throw new RefreshException("Failed to parse response from Discord refresh");
        
        db.DiscordTokens.Remove(discordToken);

        var newToken = new DiscordToken
        {
            UserId = discordToken.UserId,
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken,
            Expiry = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn)
        };

        await db.DiscordTokens.AddAsync(newToken);
        await db.SaveChangesAsync();

        return newToken;
    }

    public Task<Claim[]> GetAllClaimsAsync(long userId) =>
        memoryCache.GetOrCreateAsync<Claim[]>($"claims_{userId}", async entry =>
        {
            var discordToken = await this.GetDiscordTokenAsync(userId);
            var request = new HttpRequestMessage(HttpMethod.Get, discordOptions.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", discordToken?.AccessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await httpClient.SendAsync(request);
            var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
            var claimsIdentity = new ClaimsIdentity();
            foreach (var claimAction in discordOptions.ClaimActions)
                claimAction.Run(payload, claimsIdentity, "id.ffxivvenues.com");
            return claimsIdentity.Claims.ToArray();
        })!;

    public Task<long[]> GetGuildsForUserAsync(long userId) =>
        memoryCache.GetOrCreateAsync<long[]>($"guilds_{userId}", async entry =>
        {
            var discordToken = await GetDiscordTokenAsync(userId);
            var request = new HttpRequestMessage(HttpMethod.Get, "https://discordapp.com/api/users/@me/guilds");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", discordToken?.AccessToken);
            var response = await httpClient.SendAsync(request);
            var guilds = await response.Content.ReadFromJsonAsync<List<Guild>>();
            entry.SetSlidingExpiration(TimeSpan.FromMinutes(3));
            return guilds?
                       .Select(g => long.TryParse(g.Id, out var id) ? id : 0)
                       .Where(c => c is not 0).ToArray() 
                   ?? [];
        })!;

    public Task<long[]> GetRolesForUserInGuildAsync(long userId, long guildId) =>
        memoryCache.GetOrCreateAsync<long[]>($"guild-roles_{userId}", async entry =>
        {
            var discordToken = await GetDiscordTokenAsync(userId);
            var request = new HttpRequestMessage(HttpMethod.Get, $"https://discordapp.com/api/users/@me/guilds/{guildId}/member");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", discordToken?.AccessToken);
            var response = await httpClient.SendAsync(request);
            var guildMember = await response.Content.ReadFromJsonAsync<GuildMember>();
            entry.SetSlidingExpiration(TimeSpan.FromMinutes(3));
            return guildMember?.Roles ?? [];
        })!;
    
}

internal class RefreshException(string message) : Exception(message);

internal record Guild(string Id);
internal record GuildMember(long[] Roles);
