namespace FFXIVVenues.Identity.Connect.Clients;

public class ClientManager(IConfigurationRoot config)
{
    private readonly Client[] _clients = 
        config.GetSection("Clients").Get<Client[]>() ?? Array.Empty<Client>();

    public Client? GetClient(string clientId) =>
        this._clients.FirstOrDefault(c => c.ClientId == clientId);
}