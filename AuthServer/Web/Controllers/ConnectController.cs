using AuthServer.DataAccess.Entities;
using AuthServer.OpenId;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Web.Controllers;

// Протокольные эндпоинты без UI. Authorize и logout — Razor Pages в Web/Pages/Connect.
// Без [ApiController]: формат запросов и ошибок задаёт OAuth/OpenIddict, а не ProblemDetails.
public sealed class ConnectController(
    IOpenIddictApplicationManager applicationManager,
    UserManager<User> userManager,
    PrincipalBuilder principalBuilder,
    ILogger<ConnectController> logger) : ControllerBase
{
    private const string Scheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetRequiredOpenIddictRequest();

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Код / refresh-токен уже проверен OpenIddict (подпись, срок, PKCE, redemption).
            var result = await HttpContext.AuthenticateAsync(Scheme);

            var stored = result.Principal;
            var subject = stored?.GetClaim(Claims.Subject);

            var user = subject is null ? null : await userManager.FindByIdAsync(subject);

            // Единственное место, где отзыв доступа применяется к живой сессии при JWT-токенах.
            if (stored is null
                || user is null
                || await userManager.IsLockedOutAsync(user)
                || stored.GetClaim(PrincipalBuilder.SecurityStampClaim) != await userManager.GetSecurityStampAsync(user))
            {
                logger.LogWarning("Token request rejected for subject {Subject}: user unavailable or changed", subject);
                return Forbid(ConnectRequest.ErrorProperties(Errors.InvalidGrant, "The token is no longer valid."), Scheme);
            }

            // Principal пересобирается: роли, имя, email могли поменяться с момента логина.
            var principal = await principalBuilder.CreateUserPrincipalAsync(
                user, stored.GetScopes(), stored.GetAuthorizationId());

            logger.LogInformation("Issuing tokens for user {Subject} to client {ClientId} via {GrantType}",
                subject, request.ClientId, request.GrantType);

            return SignIn(principal, Scheme);
        }

        if (request.IsClientCredentialsGrantType())
        {
            // Scope'ы уже сверены OpenIddict с разрешениями клиента (иначе — invalid_scope).
            var application = await applicationManager.FindByClientIdAsync(request.ClientId!)
                ?? throw new InvalidOperationException("The client application cannot be found.");

            var principal = await principalBuilder.CreateClientPrincipalAsync(
                request.ClientId!,
                await applicationManager.GetDisplayNameAsync(application),
                request.GetScopes());

            logger.LogInformation("Issuing client token to {ClientId}", request.ClientId);

            return SignIn(principal, Scheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    [Authorize(AuthenticationSchemes = Scheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> UserInfo()
    {

        var user = await userManager.FindByIdAsync(User.GetClaim(Claims.Subject)!);

        if (user is null)
        {
            return Challenge(
                ConnectRequest.ErrorProperties(Errors.InvalidToken,
                    "The specified access token is bound to an account that no longer exists."),
                Scheme);
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id.ToString()
        };

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = user.DisplayName ?? user.UserName!;
            claims[Claims.PreferredUsername] = user.UserName!;
        }

        if (User.HasScope(Scopes.Email) && user.Email is not null)
        {
            claims[Claims.Email] = user.Email;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(Scopes.Roles))
            claims[Claims.Role] = await userManager.GetRolesAsync(user);

        return Ok(claims);
    }
}
