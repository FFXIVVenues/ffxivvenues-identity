using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using FFXIVVenues.Identity.Models;
using FFXIVVenues.Identity.OIDC;
using Microsoft.EntityFrameworkCore;

namespace FFXIVVenues.Identity.DiscordSignin;

public class DiscordManager(IConfiguration config, IdentityDbContext db, HttpClient httpClient, DiscordOptions discordOptions)
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

        if (!apiResponse.IsSuccessStatusCode)
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

    public async Task<Claim[]> GetAllClaimsAsync(long userId)
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
    }
}

internal class RefreshException(string message) : Exception(message);