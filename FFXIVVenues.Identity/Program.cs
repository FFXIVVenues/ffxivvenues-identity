using FFXIVVenues.Identity;
using FFXIVVenues.Identity.DiscordSignin;
using FFXIVVenues.Identity.Models;
using FFXIVVenues.Identity.OIDC;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var config = new ConfigurationBuilder()
    .AddEnvironmentVariables("FFXIVVENUES_IDENTITY__")
    .AddUserSecrets<Program>()
    .AddCommandLine(args)
    .Build();

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton(config);
builder.Services.AddSingleton<ClientManager>();
builder.Services.AddSingleton<ClaimsIdentityManager>();
builder.Services.AddSingleton<DiscordManager>();
builder.Services.AddSingleton<DiscordOptions>();
builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddDbContext<IdentityDbContext>(ServiceLifetime.Singleton);
builder.Services
    .AddAuthentication(DiscordOptions.AuthenticationScheme)
    .AddCookie()
    .AddDiscord(x => {
        x.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        x.ClientId = config.GetValue<string>("Discord:ClientId")!;
        x.ClientSecret = config.GetValue<string>("Discord:ClientSecret")!;
        var scopes = config.GetSection("Discord:Scopes").Get<string[]>();
        if (scopes is not null) foreach (var scope in scopes) x.Scope.Add(scope);
    });

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();
app.MapGet("/", (HttpContext c, IdentityDbContext db) => 
    db.DiscordTokens);

app.MapControllers();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.Services.GetService<IdentityDbContext>()!.Database.MigrateAsync();
app.Run();