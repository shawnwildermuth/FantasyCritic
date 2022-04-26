#nullable disable


using FantasyCritic.Lib.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FantasyCritic.Web.Pages.Account;

[AllowAnonymous]
public class ConfirmEmailChangeModel : PageModel
{
    private readonly FantasyCriticUserManager _userManager;
    private readonly FantasyCriticSignInManager _signInManager;

    public ConfirmEmailChangeModel(FantasyCriticUserManager userManager, FantasyCriticSignInManager signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [TempData]
    public string StatusMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(string userId, string email, string code)
    {
        if (userId == null || email == null || code == null)
        {
            return RedirectToPage("/Index");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{userId}'.");
        }

        var result = await _userManager.ChangeEmailAsync(user, email, code);
        if (!result.Succeeded)
        {
            StatusMessage = "Error changing email.";
            return Page();
        }

        await _signInManager.RefreshSignInAsync(user);
        StatusMessage = "Thank you for confirming your email change.";
        return Page();
    }
}
