using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FFXIVVenues.Identity.DiscordSignin;

[ApiController]
[Route("[controller]")]
public class DiscordRedirectController : ControllerBase
{
    [Authorize]
    [HttpGet("/authenticate/redirect")]
    public ActionResult<IEnumerable<string>> Authorize() => 
        this.Challenge();
}