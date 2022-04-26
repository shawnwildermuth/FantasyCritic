#nullable disable

using System.ComponentModel.DataAnnotations;
using FantasyCritic.Lib.Identity;
using FantasyCritic.Lib.Services;
using FantasyCritic.Web.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace FantasyCritic.Web.Pages.Account;

[AllowAnonymous]
public class RegisterModel : PageModel
{
    private readonly FantasyCriticSignInManager _signInManager;
    private readonly FantasyCriticUserManager _userManager;
    private readonly ILogger<RegisterModel> _logger;
    private readonly EmailSendingService _emailSendingService;

    public RegisterModel(FantasyCriticUserManager userManager, FantasyCriticSignInManager signInManager,
        ILogger<RegisterModel> logger, EmailSendingService emailSendingService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
        _emailSendingService = emailSendingService;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    public string ReturnUrl { get; set; }

    public AuthenticationScheme GoogleLogin { get; set; }
    public AuthenticationScheme MicrosoftLogin { get; set; }
    public AuthenticationScheme TwitchLogin { get; set; }
    public AuthenticationScheme DiscordLogin { get; set; }

    public class InputModel
    {
        [Required, MinLength(1), MaxLength(30)]
        [Display(Name = "Display Name")]
        public string DisplayName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public async Task OnGetAsync(string returnUrl = null)
    {
        ReturnUrl = returnUrl;

        var externalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        GoogleLogin = externalLogins.SingleOrDefault(x => x.Name == "Google");
        MicrosoftLogin = externalLogins.SingleOrDefault(x => x.Name == "Microsoft");
        TwitchLogin = externalLogins.SingleOrDefault(x => x.Name == "Twitch");
        DiscordLogin = externalLogins.SingleOrDefault(x => x.Name == "Discord");
    }

    public async Task<IActionResult> OnPostAsync(string returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        var externalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        GoogleLogin = externalLogins.SingleOrDefault(x => x.Name == "Google");
        MicrosoftLogin = externalLogins.SingleOrDefault(x => x.Name == "Microsoft");
        TwitchLogin = externalLogins.SingleOrDefault(x => x.Name == "Twitch");
        DiscordLogin = externalLogins.SingleOrDefault(x => x.Name == "Discord");

        if (ModelState.IsValid)
        {
            var user = new FantasyCriticUser { Id = Guid.NewGuid(), UserName = Input.DisplayName, Email = Input.Email };
            var result = await _userManager.CreateAsync(user, Input.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");

                var fullUser = await _userManager.FindByIdAsync(user.Id.ToString());
                var confirmLink = await LinkBuilder.GetConfirmEmailLink(_userManager, fullUser, Request);
                await _emailSendingService.SendConfirmationEmail(fullUser, confirmLink);

                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                }
                else
                {
                    await _signInManager.SignInAsync(fullUser, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        // If we got this far, something failed, redisplay form
        return Page();
    }
}
