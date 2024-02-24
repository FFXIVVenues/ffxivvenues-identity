using Microsoft.AspNetCore.Authentication;

namespace FFXIVVenues.Identity.DiscordSignin;

public static class DiscordAuthenticationExtensions
{
    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder)
        => builder.AddDiscord(DiscordOptions.AuthenticationScheme, _ => { });

    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder, Action<DiscordOptions> configureOptions)
        => builder.AddDiscord(DiscordOptions.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder, string authenticationScheme, Action<DiscordOptions> configureOptions)
        => builder.AddDiscord(authenticationScheme, DiscordOptions.DisplayName, configureOptions);

    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<DiscordOptions> configureOptions)
        => builder.AddOAuth<DiscordOptions, DiscordCallbackHandler>(authenticationScheme, displayName, configureOptions);
}