using Microsoft.EntityFrameworkCore;

namespace FFXIVVenues.Identity.Models;

public class IdentityDbContext(IConfiguration configuration) : DbContext
{
    private readonly string _connectionString = configuration.GetConnectionString("Identity")!;
    public required DbSet<DiscordToken> DiscordTokens { get; init; }
    public required DbSet<ClientToken> ClientTokens { get; init; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseNpgsql(this._connectionString);
        optionsBuilder.UseLazyLoadingProxies();
    }
}
