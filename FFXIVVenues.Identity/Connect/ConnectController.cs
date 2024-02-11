using Microsoft.AspNetCore.Mvc;

namespace FFXIVVenues.Identity.Connect;

[ApiController]
[Route("[controller]")]
public class ConnectController : ControllerBase
{
    [HttpGet("/.well-known/openid-configuration")]
    public ActionResult<DiscoveryObject> Discovery() =>
        new DiscoveryObject(this.HttpContext.Request.Host.ToString());
}