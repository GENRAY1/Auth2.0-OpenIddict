using AuthServer.DataAccess.Entities;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace AuthServer.Web.Pages.Connect;

// RP-initiated logout (/connect/logout). Локальный выход из cookie — /Account/Logout.
[IgnoreAntiforgeryToken]
public sealed class EndSessionModel(SignInManager<User> signInManager, IAntiforgery antiforgery) : PageModel
{
    public List<KeyValuePair<string, string?>> Parameters { get; private set; } = [];

    public Task<IActionResult> OnGetAsync() => HandleAsync();
    public Task<IActionResult> OnPostAsync() => HandleAsync();

    private async Task<IActionResult> HandleAsync()
    {
        var request = HttpContext.GetRequiredOpenIddictRequest();

        // id_token_hint уже провалидирован OpenIddict — это запрос от нашего клиента, выходим сразу.
        // Без него (или без явного подтверждения) показываем страницу: иначе любой сайт
        // может разлогинить пользователя картинкой на /connect/logout.
        if (Request.HasFormField(ConnectRequest.LogoutField))
            await antiforgery.ValidateRequestAsync(HttpContext);
        else if (string.IsNullOrEmpty(request.IdTokenHint))
        {
            Parameters = Request.GetResubmitParameters();
            return Page();
        }

        await signInManager.SignOutAsync();

        // OpenIddict сам сделает редирект на post_logout_redirect_uri, если он зарегистрирован у клиента.
        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}
