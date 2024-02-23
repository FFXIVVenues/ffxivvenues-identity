using FFXIVVenues.Identity;
using FFXIVVenues.Identity.DiscordSignin;
using FFXIVVenues.Identity.OIDC;
using FFXIVVenues.Identity.OIDC.Clients;
using Microsoft.AspNetCore.Authentication.Cookies;


var config = new ConfigurationBuilder()
    .AddEnvironmentVariables("FFXIVVENUES_IDENTITY__")
    .AddUserSecrets<Program>()
    .AddCommandLine(args)
    .Build();

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton(config);
builder.Services.AddSingleton<ClientManager>();
builder.Services.AddSingleton<ClaimsService>();
builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
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

app.MapControllers();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();