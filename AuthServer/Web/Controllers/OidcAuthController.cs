using AuthServer.OpenId.Oidc;
using AuthServer.OpenId.Oidc.Types;
using AuthServer.Startup.Options;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Client.AspNetCore;

namespace AuthServer.Web.Controllers;

public sealed class OidcAuthController(
    OidcLoginService oidcLogins,
    IOptionsMonitor<OidcProviderOptions> providerOptions,
    ILogger<OidcAuthController> logger) : Controller
{
    [HttpPost("~/external/challenge/{provider}"), ValidateAntiForgeryToken]
    public IActionResult ChallengeProvider(string provider, [FromForm] string? returnUrl)
    {
        if (!OidcProviders.DisplayNames.ContainsKey(provider) || !providerOptions.Get(provider).IsConfigured)
            return NotFound();

        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictClientAspNetCoreConstants.Properties.ProviderName] = provider
        })
        {
            // Обычно это /connect/authorize?... — после входа authorize отработает как обычно.
            RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
        };

        return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/callback/login/{provider}"), HttpPost("~/callback/login/{provider}"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Callback(string provider)
    {
        // State, подпись/срок ответа и обмен кода (с PKCE для VK ID) уже выполнены OpenIddict.Client.
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        var returnUrl = result.Properties?.RedirectUri is { } uri && Url.IsLocalUrl(uri) ? uri : "/";

        if (!result.Succeeded || result.Principal is null)
        {
            var error = HttpContext.GetOpenIddictClientResponse()?.Error ?? result.Failure?.Message;
            logger.LogWarning("External login via {Provider} failed: {Error}", provider, error);
            return RedirectToLogin(returnUrl, "Не удалось войти через внешнего провайдера.");
        }

        var outcome = await oidcLogins.SignInAsync(result.Principal, User);

        return outcome.Status switch
        {
            OidcLoginStatus.SignedIn => LocalRedirect(returnUrl),
            OidcLoginStatus.Linked => LocalRedirect(returnUrl),
            OidcLoginStatus.LockedOut => RedirectToPage("/Account/Lockout"),
            OidcLoginStatus.EmailConflict => RedirectToLogin(returnUrl, "Аккаунт с этим email уже существует. Войдите паролем и привяжите провайдера в настройках профиля."),
            OidcLoginStatus.LinkedToAnotherUser => RedirectToPage("/Account/Manage",
                new { message = "Этот внешний аккаунт уже привязан к другому пользователю." }),
            _ => RedirectToLogin(returnUrl, outcome.Error ?? "Не удалось войти через внешнего провайдера.")
        };
    }

    private RedirectToPageResult RedirectToLogin(string returnUrl, string error) =>
        RedirectToPage("/Account/Login", new { returnUrl, error });
}
