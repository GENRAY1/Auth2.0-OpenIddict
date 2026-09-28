namespace AuthServer.Startup.Options;

public sealed class SeedOptions
{
    public const string Section = "Seed";

    // Массив, а не словарь: двоеточие в имени scope ("api:internal") — разделитель секций конфигурации.
    public ScopeSeed[] Scopes { get; set; } = [];

    // Ключ — имя секции конфигурации (без дефисов, чтобы секрет задавался через env:
    // Seed__Clients__SvcExample__ClientSecret), реальный идентификатор — ClientId.
    public Dictionary<string, ClientSeed> Clients { get; set; } = [];

    // Тестовый пользователь, создаётся только в Development.
    public DevUserSeed? DevUser { get; set; }
}

public sealed class ScopeSeed
{
    public string Name { get; set; } = "";
    public string? DisplayName { get; set; }
    public string[] Resources { get; set; } = [];
}

public sealed class ClientSeed
{
    public string ClientId { get; set; } = "";
    public string? DisplayName { get; set; }

    // "public" | "confidential"
    public string Type { get; set; } = "public";

    // "implicit" | "explicit"
    public string ConsentType { get; set; } = "explicit";

    // Никогда не в appsettings.json в git: env / user-secrets / docker secrets.
    public string? ClientSecret { get; set; }

    public string[] GrantTypes { get; set; } = [];
    public string[] Scopes { get; set; } = [];
    public string[] RedirectUris { get; set; } = [];
    public string[] PostLogoutRedirectUris { get; set; } = [];

    public bool AllowIntrospection { get; set; }

    // Переопределение глобального времени жизни refresh-токена для конкретного клиента.
    public TimeSpan? RefreshTokenLifetime { get; set; }
}

public sealed class DevUserSeed
{
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
    public string[] Roles { get; set; } = [];
}
