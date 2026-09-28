using AuthServer.DataAccess.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthServer.Web.Pages.Account;

// Локальный выход из cookie AuthServer. RP-initiated logout клиентов идёт через /connect/logout.
public sealed class LogoutModel(SignInManager<User> signInManager) : PageModel
{
    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        await signInManager.SignOutAsync();
        return RedirectToPage();
    }
}
