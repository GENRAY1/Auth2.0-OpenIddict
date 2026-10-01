using AuthServer.DataAccess;
using AuthServer.DataAccess.Entities;
using AuthServer.OpenId;
using AuthServer.OpenId.Oidc;
using AuthServer.OpenId.Oidc.Types;
using AuthServer.Startup;
using AuthServer.Startup.Options;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer;

public static class DependencyInjection
{
    public static void AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("AuthPg")
                               ?? throw new InvalidOperationException("ConnectionStrings:AuthPg is not configured.");


        services.AddDbContext<DatabaseContext>(o => o.UseNpgsql(connectionString).UseOpenIddict());

        services.Configure<SeedOptions>(configuration.GetSection(SeedOptions.Section));
    }

    public static void AddWebUi(this IServiceCollection services)
    {
        // Контроллеры без Views: ConnectController (token, userinfo) и OidcAuthController (внешние провайдеры).
        services.AddControllers();

        // Весь UI — Razor Pages под /Web/Pages, включая протокольные /connect/authorize и /connect/logout.
        services.AddRazorPages(o => o.RootDirectory = "/Web/Pages");
    }

    public static void AddScheduling(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddQuartz(o =>
        {
            o.UseSimpleTypeLoader();
            o.UseInMemoryStore();
        });

        services.AddQuartzHostedService(o => o.WaitForJobsToComplete = true);
    }


    public static void AddIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentity<User, Role>(o =>
            {
                o.User.RequireUniqueEmail = false;
                o.User.AllowedUserNameCharacters += ":";
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                o.ClaimsIdentity.UserNameClaimType = Claims.Name;
                o.ClaimsIdentity.UserIdClaimType = Claims.Subject;
                o.ClaimsIdentity.RoleClaimType = Claims.Role;
            })
            .AddEntityFrameworkStores<DatabaseContext>()
            .AddDefaultTokenProviders();

        services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.FromMinutes(5));

        services.ConfigureApplicationCookie(o =>
        {
            o.LoginPath = "/Account/Login";
            o.LogoutPath = "/Account/Logout";
            o.AccessDeniedPath = "/Account/AccessDenied";
            o.Cookie.HttpOnly = true;
            o.Cookie.SameSite = SameSiteMode.Lax;
            o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            o.ExpireTimeSpan = TimeSpan.FromHours(8);
            o.SlidingExpiration = true;
        });
    }

    public static void AddOpenId(
        this IServiceCollection services,
        IConfiguration configuration,
        IWebHostEnvironment env)
    {
        AuthOptions authOptions = ConfigureAuth(services, configuration);
        Dictionary<string, OidcProviderOptions> providers = ConfigureOidcProviders(services, configuration);

        AddDataProtection(services, authOptions, env);

        services.AddOpenIddict()
            .AddCore(o =>
            {
                o.UseEntityFrameworkCore().UseDbContext<DatabaseContext>();
                o.UseQuartz();
            })
            .AddServer(o =>
            {
                o.SetIssuer(authOptions.Issuer);

                o.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetEndSessionEndpointUris("connect/logout")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetRevocationEndpointUris("connect/revoke")
                    .SetIntrospectionEndpointUris("connect/introspect");

                o.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange() // действует только на authorization_code
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow();

                // OAuth 2.1: только S256, "plain" не публикуем и не принимаем.
                o.Configure(options => options.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));

                o.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles, Scopes.OfflineAccess, "api",
                    "api:internal");

                Certificates.EnsureConfigured(env, authOptions.ServerSigningCertificate,
                    nameof(AuthOptions.ServerSigningCertificate));
                Certificates.EnsureConfigured(env, authOptions.ServerEncryptionCertificate,
                    nameof(AuthOptions.ServerEncryptionCertificate));

                if (authOptions.ServerSigningCertificate is { } signing)
                    o.AddSigningCertificate(Certificates.Load(signing));
                else
                    o.AddDevelopmentSigningCertificate();

                if (authOptions.ServerEncryptionCertificate is { } encryption)
                    o.AddEncryptionCertificate(Certificates.Load(encryption));
                else
                    o.AddDevelopmentEncryptionCertificate();

                // Access-токен — подписанный, но НЕ зашифрованный JWT. В access-токен не кладём ничего чувствительного
                o.DisableAccessTokenEncryption();

                o.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5))
                    .SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetIdentityTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetRefreshTokenLifetime(TimeSpan.FromDays(30))
                    .SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(30));
                // Rolling refresh tokens включены по умолчанию — DisableRollingRefreshTokens() не вызывать.

                var aspNet = o.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough();

                if (env.IsDevelopment())
                    aspNet.DisableTransportSecurityRequirement();
            })
            .AddValidation(o =>
            {
                o.UseLocalServer();
                o.UseAspNetCore();
            })
            .AddOidc(authOptions, providers, env);


        services.AddScoped<PrincipalBuilder>();
        services.AddScoped<OidcLoginService>();
        services.AddScoped<OpenIddictSeeder>();
    }

    private static void AddOidc(this OpenIddictBuilder builder,
        AuthOptions authOptions,
        Dictionary<string, OidcProviderOptions> providers,
        IWebHostEnvironment env)
    {
        if (providers.Count == 0) return;

        builder.AddClient(o =>
        {
            o.AllowAuthorizationCodeFlow();

            Certificates.EnsureConfigured(env, authOptions.ClientSigningCertificate,
                nameof(AuthOptions.ClientSigningCertificate));
            Certificates.EnsureConfigured(env, authOptions.ClientEncryptionCertificate,
                nameof(AuthOptions.ClientEncryptionCertificate));

            if (authOptions.ClientSigningCertificate is { } signing)
                o.AddSigningCertificate(Certificates.Load(signing));
            else
                o.AddDevelopmentSigningCertificate();

            if (authOptions.ClientEncryptionCertificate is { } encryption)
                o.AddEncryptionCertificate(Certificates.Load(encryption));
            else
                o.AddDevelopmentEncryptionCertificate();

            var aspNet = o.UseAspNetCore()
                .EnableRedirectionEndpointPassthrough();

            if (env.IsDevelopment())
                aspNet.DisableTransportSecurityRequirement();

            o.UseSystemNetHttp().SetProductInformation(typeof(Program).Assembly);

            var web = o.UseWebProviders();

            if (providers.TryGetValue(OidcProviders.Yandex, out var yandex))
                web.AddYandex(p => p
                    .SetClientId(yandex.ClientId!)
                    .SetClientSecret(yandex.ClientSecret!)
                    .SetRedirectUri("callback/login/yandex")
                    .AddScopes("login:email", "login:info"));

            if (providers.TryGetValue(OidcProviders.VkId, out var vk))
                web.AddVkId(p => p
                    .SetClientId(vk.ClientId!)
                    .SetClientSecret(vk.ClientSecret!)
                    .SetRedirectUri("callback/login/vkid")
                    .AddScopes("email"));
        });
    }

    private static void AddDataProtection(IServiceCollection services, AuthOptions authOptions, IWebHostEnvironment env)
    {
        var dataProtection = services.AddDataProtection()
            .PersistKeysToDbContext<DatabaseContext>()
            .SetApplicationName("AuthServer");

        Certificates.EnsureConfigured(env, authOptions.DataProtectionCertificate,
            nameof(AuthOptions.DataProtectionCertificate));

        if (authOptions.DataProtectionCertificate is { } dpCert)
            dataProtection.ProtectKeysWithCertificate(Certificates.Load(dpCert));
    }

    private static AuthOptions ConfigureAuth(
        IServiceCollection services,
        IConfiguration configuration)
    {
        var authOptions = configuration.GetSection(AuthOptions.Section).Get<AuthOptions>() ?? new AuthOptions();

        if (!Uri.TryCreate(authOptions.Issuer, UriKind.Absolute, out var issuer))
            throw new InvalidOperationException("Auth:Issuer must be an absolute URI.");

        services.Configure<AuthOptions>(configuration.GetSection(AuthOptions.Section));

        return authOptions;
    }

    private static Dictionary<string, OidcProviderOptions> ConfigureOidcProviders(
        IServiceCollection services,
        IConfiguration configuration)
    {
        var configured = new Dictionary<string, OidcProviderOptions>();

        foreach (var provider in OidcProviders.DisplayNames.Keys)
        {
            var section = configuration.GetSection($"{OidcProviderOptions.Section}:{provider}");
            services.Configure<OidcProviderOptions>(provider, section);

            var options = section.Get<OidcProviderOptions>();
            if (options?.IsConfigured == true)
                configured[provider] = options;
        }

        return configured;
    }
}