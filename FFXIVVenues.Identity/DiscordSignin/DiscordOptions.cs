using System.Security.Claims;
using FFXIVVenues.Identity.OIDC;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace FFXIVVenues.Identity.DiscordSignin;

public class DiscordOptions : OAuthOptions
{
    public const string AuthenticationScheme = "Discord";
    public const string DisplayName = "Discord";
    public const string TokenEndpointUri = "https://discordapp.com/api/oauth2/token";
    public const string UserInfoEndpointUri = "https://discordapp.com/api/users/@me";
    
    public DiscordOptions()
    {
        AuthorizationEndpoint = "https://discordapp.com/api/oauth2/authorize?prompt=none";
        TokenEndpoint = TokenEndpointUri;
        UserInformationEndpoint = UserInfoEndpointUri;
        CallbackPath = new PathString("/signin-discord");

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
    }
        
}