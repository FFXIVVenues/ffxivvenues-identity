using Microsoft.IdentityModel.Tokens;

namespace FFXIVVenues.Identity.Models;

public record JsonWebKeySet(params JsonWebKey[] Keys);