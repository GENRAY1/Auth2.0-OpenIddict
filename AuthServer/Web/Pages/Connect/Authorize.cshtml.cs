using System.Collections.Immutable;
using System.Security.Claims;
using AuthServer.DataAccess.Entities;
using AuthServer.OpenId;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Web.Pages.Connect;

// Authorization endpoint: протокольная логика и экран consent в одной странице.
// Первый запрос приходит от клиента без antiforgery-токена — проверяем вручную только на кнопках.
[IgnoreAntiforgeryToken]
public sealed class AuthorizeModel(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    PrincipalBuilder principalBuilder,
    IAntiforgery antiforgery) : PageModel
{
    public string ApplicationName { get; private set; } = "";
    public ImmutableArray<string> Scopes { get; private set; } = [];
    public List<KeyValuePair<string, string?>> Parameters { get; private set; } = [];

    public Task<IActionResult> OnGetAsync() => HandleAsync();
    public Task<IActionResult> OnPostAsync() => HandleAsync();

    private async Task<IActionResult> HandleAsync()
    {
        var request = HttpContext.GetRequiredOpenIddictRequest();

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
        var applicationId = await applicationManager.GetIdAsync(application)
            ?? throw new InvalidOperationException("The client application has no identifier.");
        var scopes = request.GetScopes();

        var authorizations = await authorizationManager.FindAsync(
            subject: user.Id.ToString(),
            client: applicationId,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: scopes).ToListAsync();

        switch (await applicationManager.GetConsentTypeAsync(application))
        {
            case ConsentTypes.External when authorizations.Count is 0:
                return ForbidWith(Errors.ConsentRequired,
                    "The logged in user is not allowed to access this client application.");

            case ConsentTypes.Implicit:
            case ConsentTypes.External:
            case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPromptValue(PromptValues.Consent):
                return await IssueAuthorizationAsync(user, scopes, applicationId, authorizations.LastOrDefault());

            case ConsentTypes.Explicit or ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                return ForbidWith(Errors.ConsentRequired, "Interactive user consent is required.");

            default:
                var accepted = Request.HasFormField(ConnectRequest.AcceptField);
                if (accepted || Request.HasFormField(ConnectRequest.DenyField))
                {
                    await antiforgery.ValidateRequestAsync(HttpContext);
                    return accepted
                        ? await IssueAuthorizationAsync(user, scopes, applicationId, authorization: null)
                        : ForbidWith(Errors.AccessDenied, "The user denied the authorization request.");
                }

                ApplicationName = await applicationManager.GetLocalizedDisplayNameAsync(application) ?? request.ClientId!;
                Scopes = scopes;
                Parameters = Request.GetResubmitParameters();
                return Page();
        }
    }

    private async Task<IActionResult> IssueAuthorizationAsync(
        User user, ImmutableArray<string> scopes, string applicationId, object? authorization)
    {
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

        var parameters = Request.GetParameters()
            .Where(p => p.Key != OpenIddictConstants.Parameters.Prompt)
            .ToList();

        if (!string.IsNullOrEmpty(prompt))
            parameters.Add(KeyValuePair.Create(OpenIddictConstants.Parameters.Prompt, new StringValues(prompt)));

        return Challenge(
            new AuthenticationProperties { RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters) },
            IdentityConstants.ApplicationScheme);
    }

    private static bool IsMaxAgeExceeded(OpenIddictRequest request, AuthenticateResult result) =>
        request.MaxAge is not null
        && result.Properties?.IssuedUtc is { } issued
        && DateTimeOffset.UtcNow - issued > TimeSpan.FromSeconds(request.MaxAge.Value);

    private ForbidResult ForbidWith(string error, string description) => Forbid(
        ConnectRequest.ErrorProperties(error, description),
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
