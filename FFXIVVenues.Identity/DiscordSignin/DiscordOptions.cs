using System.Security.Claims;
using System.Web;
using FFXIVVenues.Identity.OIDC;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;

namespace FFXIVVenues.Identity.DiscordSignin;

public class DiscordOptions : OAuthOptions
{
    public const string AuthenticationScheme = "Discord";
    public const string DisplayName = "Discord";
    public const string TokenEndpointUri = "https://discordapp.com/api/oauth2/token";
    public const string UserInfoEndpointUri = "https://discordapp.com/api/users/@me";
    
    public DiscordOptions()
    {
        AuthorizationEndpoint = "https://discordapp.com/api/oauth2/authorize";
        TokenEndpoint = TokenEndpointUri;
        UserInformationEndpoint = UserInfoEndpointUri;
        CallbackPath = new PathString("/signin-discord");
        this.WithDefaultClaims();

        ClaimActions.MapJsonKey(ConnectClaims.Sub, "id", ClaimValueTypes.UInteger64);
        ClaimActions.MapJsonKey(ConnectClaims.Name, "global_name", ClaimValueTypes.String);
        ClaimActions.MapJsonKey(ConnectClaims.Nickname, "global_name", ClaimValueTypes.String);
        ClaimActions.MapJsonKey(ConnectClaims.PreferredUsername, "username", ClaimValueTypes.String);
        ClaimActions.MapJsonKey(ConnectClaims.Email, "email", ClaimValueTypes.Email);
        ClaimActions.MapJsonKey(ConnectClaims.EmailVerified, "verified", ClaimValueTypes.Boolean);
        ClaimActions.MapJsonKey(ConnectClaims.MfaEnabled, "mfa_enabled", ClaimValueTypes.Boolean);
        ClaimActions.MapCustomJson(ConnectClaims.Profile, ClaimValueTypes.String, e =>
            $"https://id.ffxivvenues.com/profile");
        ClaimActions.MapCustomJson(ConnectClaims.Picture, ClaimValueTypes.String, e =>
            $"https://cdn.discordapp.com/avatars/{e.GetString("id")}/{e.GetString("avatar")}.jpg");

        this.Events.OnRedirectToAuthorizationEndpoint += OnEventsOnRedirectToAuthorizationEndpoint;
    }

    private Task OnEventsOnRedirectToAuthorizationEndpoint(RedirectContext<OAuthOptions> context)
    {
        // Ensure redirect url is always HTTPS to protect the
        // authorisation code until PKCE. This is necessary here
        // authorisation code until PKCE. This is necessary here
        // as HTTPS may be configured at the load balancer.

        var builder = new UriBuilder(context.RedirectUri);
        var queryString = QueryHelpers.ParseQuery(builder.Query);
        var redirectUriExists = queryString.TryGetValue("redirect_uri", out var redirectUriStr);
        if (redirectUriExists)
        {
            var redirectUri = new UriBuilder(redirectUriStr!);
            redirectUri.Scheme = "https";
            redirectUri.Port = -1;
            queryString["redirect_uri"] = redirectUri.ToString();
            builder.Query = QueryHelpers.AddQueryString("", queryString);
            context.RedirectUri = builder.ToString();
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    }

    public DiscordOptions WithClaims(string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        
        Scope.Clear();
        foreach (var scope in scopes) 
            Scope.Add(scope);
        return this;
    }

    public DiscordOptions WithDefaultClaims()
    {
        Scope.Clear();
        Scope.Add("identify");
        Scope.Add("email");
        Scope.Add("guilds");
        Scope.Add("guilds.members.read");
        return this;
    }

    public DiscordOptions WithPrompt(string promptValue)
    {
        AuthorizationEndpoint = $"https://discordapp.com/api/oauth2/authorize?prompt={promptValue}";
        return this;
    }
        
}