using System.Security.Claims;
using AuthServer.DataAccess.Entities;
using AuthServer.OpenId;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Web.Controllers;

public sealed class AuthController(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    PrincipalBuilder principalBuilder,
    IAntiforgery antiforgery,
    ILogger<AuthController> logger) : Controller
{
    public const string ConsentAcceptField = "submit.Accept";
    public const string ConsentDenyField = "submit.Deny";

    [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (!result.Succeeded || request.HasPromptValue(PromptValues.Login) || IsMaxAgeExceeded(request, result))
        {
            if (request.HasPromptValue(PromptValues.None))
                return ForbidWith(Errors.LoginRequired, "The user is not logged in.");

            return ChallengeLogin(request);
        }

        var user = await userManager.GetUserAsync(result.Principal);
        if (user is null || !await signInManager.CanSignInAsync(user))
        {
            // Cookie есть, а пользователя уже нет / вход запрещён — сбрасываем cookie и идём на логин.
            await signInManager.SignOutAsync();
            return ChallengeLogin(request);
        }

        var application = await applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The client application cannot be found.");
        var applicationId = await applicationManager.GetIdAsync(application);

        var authorizations = await authorizationManager.FindAsync(
            subject: user.Id.ToString(),
            client: applicationId,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        switch (await applicationManager.GetConsentTypeAsync(application))
        {
            case ConsentTypes.External when authorizations.Count is 0:
                return ForbidWith(Errors.ConsentRequired,
                    "The logged in user is not allowed to access this client application.");

            case ConsentTypes.Implicit:
            case ConsentTypes.External:
            case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPromptValue(PromptValues.Consent):
                return await IssueAuthorizationAsync(user, request, applicationId!, authorizations.LastOrDefault());

            case ConsentTypes.Explicit or ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                return ForbidWith(Errors.ConsentRequired, "Interactive user consent is required.");

            default:
                if (Request.HasFormContentType && Request.Form.ContainsKey(ConsentAcceptField))
                {
                    await antiforgery.ValidateRequestAsync(HttpContext);
                    return await IssueAuthorizationAsync(user, request, applicationId!, authorization: null);
                }

                if (Request.HasFormContentType && Request.Form.ContainsKey(ConsentDenyField))
                {
                    await antiforgery.ValidateRequestAsync(HttpContext);
                    return ForbidWith(Errors.AccessDenied, "The user denied the authorization request.");
                }

                return View("Consent", new ConsentViewModel(
                    ApplicationName: await applicationManager.GetLocalizedDisplayNameAsync(application) ?? request.ClientId!,
                    Scopes: request.GetScopes(),
                    Parameters: FlattenRequestParameters()));
        }
    }

    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Код / refresh-токен уже проверен OpenIddict (подпись, срок, PKCE, redemption).
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var subject = result.Principal?.GetClaim(Claims.Subject);

            var user = subject is null ? null : await userManager.FindByIdAsync(subject);

            // Единственное место, где отзыв доступа применяется к живой сессии при JWT-токенах.
            if (user is null
                || !await signInManager.CanSignInAsync(user)
                || await userManager.IsLockedOutAsync(user)
                || result.Principal!.GetClaim(PrincipalBuilder.SecurityStampClaim) != await userManager.GetSecurityStampAsync(user))
            {
                logger.LogWarning("Token request rejected for subject {Subject}: user unavailable or changed", subject);
                return ForbidWith(Errors.InvalidGrant, "The token is no longer valid.");
            }

            // Principal пересобирается: роли, имя, email могли поменяться с момента логина.
            var principal = await principalBuilder.CreateUserPrincipalAsync(
                user, result.Principal!.GetScopes(), result.Principal!.GetAuthorizationId());

            logger.LogInformation("Issuing tokens for user {Subject} to client {ClientId} via {GrantType}",
                subject, request.ClientId, request.GrantType);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> UserInfo()
    {
        var user = await userManager.FindByIdAsync(User.GetClaim(Claims.Subject)!);
        if (user is null)
        {
            return Challenge(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified access token is bound to an account that no longer exists."
                }),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

    [HttpGet("~/connect/logout"), HttpPost("~/connect/logout"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // id_token_hint уже провалидирован OpenIddict — это запрос от нашего клиента, выходим сразу.
        // Без него (или без явного подтверждения) показываем страницу: иначе любой сайт
        // может разлогинить пользователя картинкой на /connect/logout.
        var confirmed = Request.HasFormContentType && Request.Form.ContainsKey("submit.Logout");
        if (confirmed)
            await antiforgery.ValidateRequestAsync(HttpContext);
        else if (string.IsNullOrEmpty(request.IdTokenHint))
            return View("LogoutConfirm", FlattenRequestParameters());

        await signInManager.SignOutAsync();

        // OpenIddict сам сделает редирект на post_logout_redirect_uri, если он зарегистрирован у клиента.
        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> IssueAuthorizationAsync(
        User user, OpenIddictRequest request, string applicationId, object? authorization)
    {
        var scopes = request.GetScopes();

        // Постоянная авторизация: список активных «сессий» пользователя и точка массового отзыва.
        authorization ??= await authorizationManager.CreateAsync(
            principal: new ClaimsPrincipal(new ClaimsIdentity()).SetScopes(scopes),
            subject: user.Id.ToString(),
            client: applicationId,
            type: AuthorizationTypes.Permanent,
            scopes: scopes);

        var principal = await principalBuilder.CreateUserPrincipalAsync(
            user, scopes, await authorizationManager.GetIdAsync(authorization));

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private IActionResult ChallengeLogin(OpenIddictRequest request)
    {
        // prompt=login убираем, иначе после входа снова попадём сюда же и зациклимся.
        var prompt = string.Join(" ", request.GetPromptValues().Remove(PromptValues.Login));

        var parameters = (Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
            .Where(p => p.Key != Parameters.Prompt)
            .ToList();

        if (!string.IsNullOrEmpty(prompt))
            parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

        return Challenge(
            new AuthenticationProperties { RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters) },
            IdentityConstants.ApplicationScheme);
    }

    // Параметры исходного запроса для повторной отправки формой (consent / подтверждение выхода).
    private List<KeyValuePair<string, string?>> FlattenRequestParameters() =>
        (Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
            .Where(p => p.Key is not (ConsentAcceptField or ConsentDenyField or "submit.Logout" or "__RequestVerificationToken"))
            .SelectMany(p => p.Value, (p, v) => KeyValuePair.Create(p.Key, v))
            .ToList();

    private static bool IsMaxAgeExceeded(OpenIddictRequest request, AuthenticateResult result) =>
        request.MaxAge is not null
        && result.Properties?.IssuedUtc is { } issued
        && DateTimeOffset.UtcNow - issued > TimeSpan.FromSeconds(request.MaxAge.Value);

    private ForbidResult ForbidWith(string error, string description) => Forbid(
        new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }),
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}

public sealed record ConsentViewModel(
    string ApplicationName,
    IReadOnlyCollection<string> Scopes,
    IReadOnlyList<KeyValuePair<string, string?>> Parameters);
