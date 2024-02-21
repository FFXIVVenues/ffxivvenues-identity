using System.Security.Claims;
using System.Security.Principal;

namespace FFXIVVenues.Identity.Identity;

public class UserService(IHttpContextAccessor httpContextAccessor)
{

    public IIdentity? GetIdentity()
    {
        if (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated != true)
            return null;
        return httpContextAccessor.HttpContext.User.Identity;
    }
    
    public User? GetCurrentUser()
    {
        if (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated != true)
            return null;
        
        var user = new User();
        string? avatar = null;
        string? banner = null;
        foreach (var claim in httpContextAccessor.HttpContext.User.Claims)
        {
            switch (claim.Type)
            {
                case ClaimTypes.Sid:
                    user.Id = claim.Value;
                    break;
                case ClaimTypes.Name:
                    user.DisplayName = claim.Value;
                    break;
                case ClaimTypes.NameIdentifier:
                    user.Username = claim.Value;
                    break;
                case ClaimTypes.Email:
                    user.Username = claim.Value;
                    break;
                case DiscordClaimTypes.Avatar:
                    avatar = claim.Value;
                    break;
                case DiscordClaimTypes.Banner:
                    banner = claim.Value;
                    break;
                case DiscordClaimTypes.Verified:
                    user.Verified = bool.TryParse(claim.Value, out var value) && value;
                    break;
            }
        }

        if (avatar != null)
            user.AvatarUri = $"https://cdn.discordapp.com/avatars/{user.Id}/{avatar}.jpg";
        if (banner != null)
            user.BannerUri = $"https://cdn.discordapp.com/banners/{user.Id}/{banner}.jpg";

        return user;
    }
    
}

public class User
{
    public string? Id { get; set; }
    public string? Username { get; set; }
    public string? DisplayName { get; set; }
    public string? AvatarUri { get; set; }
    public string? BannerUri { get; set; }
    public bool? Verified { get; set; }
}