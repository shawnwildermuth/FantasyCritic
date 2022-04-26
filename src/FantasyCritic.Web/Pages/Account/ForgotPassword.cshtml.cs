#nullable disable


using System.ComponentModel.DataAnnotations;
using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Services;
using FantasyCritic.Web.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace FantasyCritic.Web.Pages.Account;

[AllowAnonymous]
public class ForgotPasswordModel : PageModel
{
    private readonly FantasyCriticUserManager _userManager;
    private readonly EmailSendingService _emailSendingService;

    public ForgotPasswordModel(FantasyCriticUserManager userManager, EmailSendingService emailSendingService)
    {
        _userManager = userManager;
        _emailSendingService = emailSendingService;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return RedirectToPage("./ForgotPasswordConfirmation");
            }

            var forgotPasswordLink = await LinkBuilder.GetForgotPasswordLink(_userManager, user, Request);
            await _emailSendingService.SendForgotPasswordEmail(user, forgotPasswordLink);

            return RedirectToPage("./ForgotPasswordConfirmation");
        }

        return Page();
    }
}
