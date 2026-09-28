using System.Security.Claims;
using AuthServer.DataAccess.Entities;
using AuthServer.OpenId.Oidc.Types;
using AuthServer.Startup.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.OpenId.Oidc;



public sealed class OidcLoginService(
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    IOptionsMonitor<OidcProviderOptions> providerOptions,
    ILogger<OidcLoginService> logger)
{
    /// <param name="external">Principal от OpenIddict.Client (WebIntegration уже нормализовал клеймы).</param>
    /// <param name="current">Текущий пользователь по cookie; если залогинен — это привязка, а не вход.</param>
    public async Task<OidcLoginResult> SignInAsync(ClaimsPrincipal external, ClaimsPrincipal current)
    {
        var provider = external.GetClaim(Claims.Private.ProviderName);
        // providerKey — стабильный id у провайдера (id у Yandex, user_id у VK), не email.
        var providerKey = external.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(providerKey))
            return new(OidcLoginStatus.Failed, "Провайдер не вернул идентификатор пользователя.");

        var email = NullIfEmpty(external.FindFirst(ClaimTypes.Email)?.Value);
        var displayName = NullIfEmpty(external.FindFirst(ClaimTypes.Name)?.Value);
        var login = new UserLoginInfo(provider, providerKey, provider);

        var user = await userManager.FindByLoginAsync(provider, providerKey);

        if (current.Identity?.IsAuthenticated == true)
            return await LinkToCurrentAsync(current, user, login);

        if (user is not null)
            return await SignInExistingAsync(user);

        if (email is not null && await userManager.FindByEmailAsync(email) is { } existing)
        {
            if (!providerOptions.Get(provider).AutoLinkByEmail || !existing.EmailConfirmed)
            {
                logger.LogInformation("External login {Provider} matches existing email, auto-link disabled", provider);
                return new(OidcLoginStatus.EmailConflict);
            }

            var linked = await userManager.AddLoginAsync(existing, login);
            if (!linked.Succeeded)
                return Failed(linked);

            logger.LogInformation("Auto-linked {Provider} login to user {UserId} by email", provider, existing.Id);
            return await SignInExistingAsync(existing);
        }

        user = new User
        { 
            UserName = $"{provider.ToLowerInvariant()}:{providerKey}",
            Email = email,
            EmailConfirmed = false,
            DisplayName = displayName
        };

        var created = await userManager.CreateAsync(user);
        
        if (!created.Succeeded)
            return Failed(created);

        var added = await userManager.AddLoginAsync(user, login);
        if (!added.Succeeded)
        {
            await userManager.DeleteAsync(user);
            return Failed(added);
        }

        logger.LogInformation("Created user {UserId} from {Provider} login", user.Id, provider);
        return await SignInExistingAsync(user);
    }

    private async Task<OidcLoginResult> LinkToCurrentAsync(
        ClaimsPrincipal current,
        User? owner,
        UserLoginInfo login)
    {
        var me = await userManager.GetUserAsync(current);
        
        if (me is null)
            return new(OidcLoginStatus.Failed, "Текущий пользователь не найден.");

        if (owner is not null)
            return owner.Id == me.Id
                ? new(OidcLoginStatus.Linked)
                : new(OidcLoginStatus.LinkedToAnotherUser);

        var result = await userManager.AddLoginAsync(me, login);
        if (!result.Succeeded)
            return Failed(result);

        logger.LogInformation("Linked {Provider} login to user {UserId}", login.LoginProvider, me.Id);
        return new(OidcLoginStatus.Linked);
    }

    private async Task<OidcLoginResult> SignInExistingAsync(User user)
    {
        if (await userManager.IsLockedOutAsync(user))
            return new(OidcLoginStatus.LockedOut);

        if (!await signInManager.CanSignInAsync(user))
            return new(OidcLoginStatus.Failed, "Вход для этого аккаунта запрещён.");

        await signInManager.SignInAsync(user, isPersistent: false);
        return new(OidcLoginStatus.SignedIn);
    }

    private static OidcLoginResult Failed(IdentityResult result) =>
        new(OidcLoginStatus.Failed, string.Join(" ", result.Errors.Select(e => e.Description)));

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
