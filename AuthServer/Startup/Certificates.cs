using System.Security.Cryptography.X509Certificates;
using AuthServer.Startup.Options;

namespace AuthServer.Startup;

public static class Certificates
{
    public static X509Certificate2 Load(CertificateOptions options) =>
        X509CertificateLoader.LoadPkcs12FromFile(options.Path, options.Password, X509KeyStorageFlags.EphemeralKeySet);

    public static void EnsureConfigured(IHostEnvironment env, CertificateOptions? options, string name)
    {
        if (options is null && !env.IsDevelopment())
            throw new InvalidOperationException($"Auth:{name} must be configured outside Development.");
    }
}
