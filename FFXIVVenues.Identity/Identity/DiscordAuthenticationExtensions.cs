using Microsoft.AspNetCore.Authentication;

namespace FFXIVVenues.Identity.Identity;

public static class DiscordAuthenticationExtensions
{
    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder)
        => builder.AddDiscord(DiscordDefaults.AuthenticationScheme, _ => { });

    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder, Action<DiscordOptions> configureOptions)
        => builder.AddDiscord(DiscordDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder, string authenticationScheme, Action<DiscordOptions> configureOptions)
        => builder.AddDiscord(authenticationScheme, DiscordDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddDiscord(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<DiscordOptions> configureOptions)
        => builder.AddOAuth<DiscordOptions, DiscordHandler>(authenticationScheme, displayName, configureOptions);
}