using AuthServer.DataAccess.Entities;
using AuthServer.OpenId.Oidc.Types;
using AuthServer.Startup.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AuthServer.Web.Pages.Account;

public sealed class LoginModel(
    UserManager<User> userManager,
    SignInManager<User> signInManager,
    IOptionsMonitor<OidcProviderOptions> providerOptions,
    ILogger<LoginModel> logger) : PageModel
{
    [BindProperty] public InputModel Input { get; set; } = new();
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    [BindProperty(SupportsGet = true)] public string? Error { get; set; }

    public IReadOnlyDictionary<string, string> Providers { get; private set; } = new Dictionary<string, string>();

    public sealed class InputModel
    {
        public string Login { get; set; } = "";
        public string Password { get; set; } = "";
        public bool RememberMe { get; set; }
    }

    public void OnGet()
    {
        ReturnUrl = SafeReturnUrl();
        Providers = OidcProviders.Get(providerOptions);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        ReturnUrl = SafeReturnUrl();
        Providers = OidcProviders.Get(providerOptions);

        var user = await userManager.FindByEmailAsync(Input.Login) ?? await userManager.FindByNameAsync(Input.Login);
        if (user is null)
        {
            logger.LogInformation("Login failed: unknown user");
            Error = "Неверный логин или пароль.";
            return Page();
        }

        var result = await signInManager.PasswordSignInAsync(user, Input.Password, Input.RememberMe, lockoutOnFailure: true);

        if (result.Succeeded)
            return LocalRedirect(ReturnUrl);

        if (result.IsLockedOut)
        {
            logger.LogWarning("User {UserId} locked out", user.Id);
            return RedirectToPage("./Lockout");
        }

        logger.LogInformation("Login failed for user {UserId}", user.Id);
        Error = result.IsNotAllowed ? "Вход для этого аккаунта запрещён." : "Неверный логин или пароль.";
        return Page();
    }

    private string SafeReturnUrl() => Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "/";
}
