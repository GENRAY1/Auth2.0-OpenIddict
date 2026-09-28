using System.Collections.Immutable;
using System.Security.Claims;
using AuthServer.DataAccess.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.OpenId;

// Единственное место, где ApplicationUser превращается в ClaimsPrincipal для OpenIddict.
// Эндпоинты дальше работают только с готовым principal.
public sealed class PrincipalBuilder(
    UserManager<User> userManager,
    IOpenIddictScopeManager scopeManager)
{
    // Клейм без destinations: попадает только в зашифрованные authorization code / refresh token,
    // в access/id token не уходит. По нему /connect/token замечает смену пароля, блокировку и т.п.
    public const string SecurityStampClaim = "security_stamp";

    public async Task<ClaimsPrincipal> CreateUserPrincipalAsync(User user, ImmutableArray<string> scopes, string? authorizationId)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, user.Id.ToString())
                .SetClaim(Claims.Name, user.DisplayName ?? user.UserName)
                .SetClaim(Claims.PreferredUsername, user.UserName)
                .SetClaim(Claims.Email, user.Email)
                .SetClaim(Claims.EmailVerified, user.Email is null ? null : user.EmailConfirmed)
                .SetClaims(Claims.Role, [.. await userManager.GetRolesAsync(user)])
                .SetClaim(SecurityStampClaim, await userManager.GetSecurityStampAsync(user));

        await ApplyScopesAsync(identity, scopes);
        identity.SetAuthorizationId(authorizationId);
        identity.SetDestinations(GetUserClaimDestinations);

        return new ClaimsPrincipal(identity);
    }

    public async Task<ClaimsPrincipal> CreateClientPrincipalAsync(
        string clientId, string? displayName, ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, clientId)
                .SetClaim(Claims.Name, displayName ?? clientId);

        await ApplyScopesAsync(identity, scopes);
        identity.SetDestinations(static claim => claim.Type switch
        {
            Claims.Name => [Destinations.AccessToken],
            _ => []
        });

        return new ClaimsPrincipal(identity);
    }

    private async Task ApplyScopesAsync(ClaimsIdentity identity, ImmutableArray<string> scopes)
    {
        identity.SetScopes(scopes);
        // Resources зарегистрированных scope'ов → `aud` access-токена.
        identity.SetResources(await scopeManager.ListResourcesAsync(scopes).ToListAsync());
    }

    // Access-токен не шифруется (DisableAccessTokenEncryption) — туда только необходимый минимум.
    // Профиль (name, email) — в id_token и /connect/userinfo.
    private static IEnumerable<string> GetUserClaimDestinations(Claim claim)
    {
        var identity = claim.Subject!;

        switch (claim.Type)
        {
            case Claims.Role:
                yield return Destinations.AccessToken;
                if (identity.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;
                yield break;

            case Claims.Name or Claims.PreferredUsername when identity.HasScope(Scopes.Profile):
                yield return Destinations.IdentityToken;
                yield break;

            case Claims.Email or Claims.EmailVerified when identity.HasScope(Scopes.Email):
                yield return Destinations.IdentityToken;
                yield break;

            // SecurityStampClaim и всё прочее — никуда.
            default:
                yield break;
        }
    }
}
