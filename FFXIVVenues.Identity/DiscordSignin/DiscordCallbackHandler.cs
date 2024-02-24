using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;

namespace FFXIVVenues.Identity.DiscordSignin;

public class DiscordCallbackHandler(DiscordManager discordManager, IOptionsMonitor<DiscordOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
    : OAuthHandler<DiscordOptions>(options, logger, encoder, clock)
{
    protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var response = await Backchannel.SendAsync(request, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"Failed to retrieve Discord user information ({response.StatusCode}).");

        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();


        var userIdStr = payload.GetString("id");
        if (userIdStr is not { Length: > 0})
            throw new HttpRequestException($"Failed to retrieve Discord user information (no user Id in response).");

        if (!long.TryParse(userIdStr, out var userId))
            throw new HttpRequestException($"Failed to retrieve Discord user information (user Id not parsable).");

        if (!int.TryParse(tokens.ExpiresIn, out var expiresIn))
            throw new HttpRequestException($"Failed to retrieve Discord user information (expiresIn not parsable).");

        if (tokens.AccessToken is null || tokens.RefreshToken is null)
            throw new AuthenticationException("Could not authenticate with Discord (Access Token or Refresh Token is missing).");
        
        await discordManager.StoreDiscordTokensAsync(userId, tokens.AccessToken, tokens.RefreshToken, expiresIn);
            
        var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload);
        context.RunClaimActions();

        await Events.CreatingTicket(context);
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }
}