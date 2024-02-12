using FFXIVVenues.Identity;
using FFXIVVenues.Identity.Connect;
using FFXIVVenues.Identity.Connect.Clients;
using FFXIVVenues.Identity.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;


var config = new ConfigurationBuilder()
    .AddEnvironmentVariables("FFXIVVENUES_IDENTITY:")
    .AddUserSecrets<Program>()
    .AddCommandLine(args)
    .Build();

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton(config);
builder.Services.AddSingleton<ClientManager>();
builder.Services.AddSingleton<UserService>();
builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services
    .AddAuthentication(DiscordDefaults.AuthenticationScheme)
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