using AuthServer.DataAccess.Entities;
using AuthServer.Startup.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Startup;

// Идемпотентный: клиенты и scope'ы описаны в конфигурации, при каждом старте создаются или обновляются.
public sealed class OpenIddictSeeder(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictScopeManager scopeManager,
    UserManager<User> userManager,
    RoleManager<Role> roleManager,
    IOptions<SeedOptions> seedOptions,
    IHostEnvironment environment,
    ILogger<OpenIddictSeeder> logger)
{
    public async Task SeedAsync(CancellationToken ct)
    {
        var seed = seedOptions.Value;

        foreach (var scope in seed.Scopes)
            await UpsertScopeAsync(scope, ct);

        foreach (var (key, client) in seed.Clients)
            await UpsertClientAsync(key, client, ct);

        if (environment.IsDevelopment() && seed.DevUser is { Email.Length: > 0, Password.Length: > 0 } devUser)
            await EnsureDevUserAsync(devUser);
    }

    private async Task UpsertScopeAsync(ScopeSeed seed, CancellationToken ct)
    {
        var name = seed.Name;
        var descriptor = new OpenIddictScopeDescriptor { Name = name, DisplayName = seed.DisplayName };
        descriptor.Resources.UnionWith(seed.Resources);

        if (await scopeManager.FindByNameAsync(name, ct) is { } existing)
            await scopeManager.UpdateAsync(existing, descriptor, ct);
        else
            await scopeManager.CreateAsync(descriptor, ct);
    }

    private async Task UpsertClientAsync(string key, ClientSeed seed, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(seed.ClientId))
            throw new InvalidOperationException($"Seed:Clients:{key}:ClientId is required.");

        var isConfidential = string.Equals(seed.Type, ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase);
        if (isConfidential && string.IsNullOrEmpty(seed.ClientSecret))
        {
            logger.LogWarning("Client {ClientId} skipped: secret is not configured (Seed:Clients:{Key}:ClientSecret)",
                seed.ClientId, key);
            return;
        }

        var descriptor = BuildDescriptor(seed, isConfidential);
        var existing = await applicationManager.FindByClientIdAsync(seed.ClientId, ct);

        if (existing is null)
        {
            await applicationManager.CreateAsync(descriptor, ct);
            logger.LogInformation("Client {ClientId} created", seed.ClientId);
        }
        else
        {
            // Секрет перехэшируется при каждом старте — ротация сводится к смене значения в secret store.
            await applicationManager.UpdateAsync(existing, descriptor, ct);
            logger.LogInformation("Client {ClientId} updated", seed.ClientId);
        }
    }

    private static OpenIddictApplicationDescriptor BuildDescriptor(ClientSeed seed, bool isConfidential)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = seed.ClientId,
            ClientSecret = isConfidential ? seed.ClientSecret : null,
            ClientType = isConfidential ? ClientTypes.Confidential : ClientTypes.Public,
            ConsentType = seed.ConsentType.ToLowerInvariant(),
            DisplayName = seed.DisplayName ?? seed.ClientId
        };

        foreach (var uri in seed.RedirectUris)
            descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
        foreach (var uri in seed.PostLogoutRedirectUris)
            descriptor.PostLogoutRedirectUris.Add(new Uri(uri, UriKind.Absolute));

        var permissions = descriptor.Permissions;

        foreach (var grantType in seed.GrantTypes)
        {
            permissions.Add(Permissions.Prefixes.GrantType + grantType);

            switch (grantType)
            {
                case GrantTypes.AuthorizationCode:
                    permissions.UnionWith([
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Revocation,
                        Permissions.ResponseTypes.Code
                    ]);
                    if (seed.PostLogoutRedirectUris.Length > 0)
                        permissions.Add(Permissions.Endpoints.EndSession);
                    if (!isConfidential)
                        descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
                    break;

                case GrantTypes.RefreshToken:
                    permissions.UnionWith([Permissions.Endpoints.Token, Permissions.Endpoints.Revocation]);
                    break;

                case GrantTypes.ClientCredentials:
                    permissions.Add(Permissions.Endpoints.Token);
                    break;

                default:
                    throw new InvalidOperationException($"Grant type '{grantType}' is not supported by the seeder.");
            }
        }

        if (seed.AllowIntrospection)
            permissions.Add(Permissions.Endpoints.Introspection);

        // openid и offline_access разрешениями не управляются: offline_access даёт право на refresh_token grant.
        foreach (var scope in seed.Scopes.Except([Scopes.OpenId, Scopes.OfflineAccess]))
            permissions.Add(Permissions.Prefixes.Scope + scope);

        if (seed.RefreshTokenLifetime is { } lifetime)
            descriptor.Settings[Settings.TokenLifetimes.RefreshToken] = lifetime.ToString("c");

        return descriptor;
    }

    private async Task EnsureDevUserAsync(DevUserSeed seed)
    {
        foreach (var role in seed.Roles)
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new Role(role));

        if (await userManager.FindByEmailAsync(seed.Email) is not null)
            return;

        var user = new User { UserName = seed.Email, Email = seed.Email, EmailConfirmed = true };
        var result = await userManager.CreateAsync(user, seed.Password);
        if (!result.Succeeded)
            throw new InvalidOperationException(
                "Dev user creation failed: " + string.Join(" ", result.Errors.Select(e => e.Description)));

        if (seed.Roles.Length > 0)
            await userManager.AddToRolesAsync(user, seed.Roles);

        logger.LogInformation("Development user {Email} created", seed.Email);
    }
}
