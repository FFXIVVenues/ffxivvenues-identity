using FFXIVVenues.Identity;
using FFXIVVenues.Identity.DiscordSignin;
using FFXIVVenues.Identity.Models;
using FFXIVVenues.Identity.OIDC;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Serilog.Events;

var config = new ConfigurationBuilder()
    .AddEnvironmentVariables("FFXIVVENUES_IDENTITY:")
    .AddUserSecrets<Program>()
    .AddCommandLine(args)
    .Build();

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Is(config.GetValue<LogEventLevel>("Logging:MinimumLevel"))
    .Enrich.WithProperty("InstanceId", Guid.NewGuid().ToString("n"))
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddConfiguration(config);
builder.Logging.AddSerilog();
builder.Services.AddSingleton(config);
builder.Services.AddSingleton<ClientManager>();
builder.Services.AddSingleton<SessionIdentityManager>();
builder.Services.AddSingleton<DiscordManager>();
builder.Services.AddSingleton<DiscordOptions>();
builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddMemoryCache();
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddDbContext<IdentityDbContext>(ServiceLifetime.Singleton);
builder.Services
    .AddAuthentication(DiscordOptions.AuthenticationScheme)
    .AddCookie()
    .AddDiscord(x => {
        x.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        x.ClientId = config.GetValue<string>("Discord:ClientId")!;
        x.ClientSecret = config.GetValue<string>("Discord:ClientSecret")!;
        var scopes = config.GetSection("Discord:Scopes").Get<string[]>();
        if (scopes is not null) x.WithClaims(scopes);
        var prompt = config.GetValue<string>("Discord:Prompt");
        if (prompt is not null) x.WithPrompt(prompt);
    });


var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStaticFiles();
app.UseAntiforgery();
app.MapControllers();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.Services.GetService<IdentityDbContext>()!.Database.MigrateAsync();
app.Run();