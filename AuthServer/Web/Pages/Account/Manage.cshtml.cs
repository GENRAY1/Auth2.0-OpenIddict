using AuthServer.DataAccess.Entities;
using AuthServer.OpenId.Oidc.Types;
using AuthServer.Startup.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AuthServer.Web.Pages.Account;

[Authorize]
public sealed class ManageModel(
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    IOptionsMonitor<OidcProviderOptions> providerOptions) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Message { get; set; }

    public string UserName { get; private set; } = "";
    public IList<UserLoginInfo> Logins { get; private set; } = [];
    public IReadOnlyDictionary<string, string> LinkableProviders { get; private set; } = new Dictionary<string, string>();
    public bool CanRemoveLogin { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
            return Challenge();

        await LoadAsync(user);
        return Page();
    }

    public async Task<IActionResult> OnPostRemoveAsync(string provider, string providerKey)
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
            return Challenge();

        await LoadAsync(user);
        if (!CanRemoveLogin)
            return RedirectToPage(new { message = "Нельзя отвязать единственный способ входа." });

        var result = await userManager.RemoveLoginAsync(user, provider, providerKey);
        if (!result.Succeeded)
            return RedirectToPage(new { message = "Не удалось отвязать вход." });

        // RemoveLoginAsync меняет SecurityStamp — перевыпускаем cookie, чтобы не выкинуло из текущей сессии.
        await signInManager.RefreshSignInAsync(user);
        return RedirectToPage();
    }

    private async Task LoadAsync(User user)
    {
        UserName = user.DisplayName ?? user.Email ?? user.UserName!;
        Logins = await userManager.GetLoginsAsync(user);
        foreach (var login in Logins)
            login.ProviderDisplayName = OidcProviders.DisplayNames.GetValueOrDefault(login.LoginProvider, login.LoginProvider);

        CanRemoveLogin = await userManager.HasPasswordAsync(user) || Logins.Count > 1;
        LinkableProviders = OidcProviders.Get(providerOptions)
            .Where(p => Logins.All(l => l.LoginProvider != p.Key))
            .ToDictionary();
    }
}
