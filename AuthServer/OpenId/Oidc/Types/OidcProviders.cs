using AuthServer.Startup.Options;
using Microsoft.Extensions.Options;

namespace AuthServer.OpenId.Oidc.Types;

public static class OidcProviders
{
    public const string Yandex = "Yandex";
    public const string VkId = "Vk";

    public static readonly IReadOnlyDictionary<string, string> DisplayNames = new Dictionary<string, string>
    {
        [Yandex] = "Яндекс",
        [VkId] = "VK ID"
    };
    
    public static IReadOnlyDictionary<string, string> Get(IOptionsMonitor<OidcProviderOptions> options) =>
        DisplayNames
            .Where(p => options.Get(p.Key).IsConfigured)
            .ToDictionary(p => p.Key, p => p.Value);
}
