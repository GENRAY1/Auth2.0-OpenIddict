namespace AuthServer.Startup.Options;

public sealed class OidcProviderOptions
{
    public const string Section = "OIDCProviders";

    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    
    public bool AutoLinkByEmail { get; set; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
