namespace AuthServer.Startup.Options;

public sealed class AuthOptions
{
    public const string Section = "Auth";

    public string Issuer { get; set; } = "";

    public bool ApplyMigrationsOnStartup { get; set; }

    // null → Development-сертификаты (разрешено только в Development).
    public CertificateOptions? ServerSigningCertificate { get; set; }
    public CertificateOptions? ServerEncryptionCertificate { get; set; }
    public CertificateOptions? ClientSigningCertificate { get; set; }
    public CertificateOptions? ClientEncryptionCertificate { get; set; }
    public CertificateOptions? DataProtectionCertificate { get; set; }
}

public sealed class CertificateOptions
{
    public string Path { get; set; } = "";
    public string? Password { get; set; }
}
