using System.Security.Claims;
using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FantasyCritic.Lib.Identity;
public class FantasyCriticSignInManager : SignInManager<FantasyCriticUser>
{
    private readonly IHttpContextAccessor _contextAccessor;

    public FantasyCriticSignInManager(UserManager<FantasyCriticUser> userManager, IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<FantasyCriticUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<FantasyCriticUser>> logger, IAuthenticationSchemeProvider schemes, IUserConfirmation<FantasyCriticUser> confirmation)
        : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
        _contextAccessor = contextAccessor;
    }

    public override Task<SignInResult> PasswordSignInAsync(FantasyCriticUser user, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var result = base.PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        AddClaim();
        return result;
    }

    public override Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var result = base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
        AddClaim();
        return result;
    }

    public override Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent)
    {
        var result = base.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent);
        AddClaim();
        return result;
    }

    public override Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor)
    {
        var result = base.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor);
        AddClaim();
        return result;
    }

    public override Task RefreshSignInAsync(FantasyCriticUser user)
    {
        var result = base.RefreshSignInAsync(user);
        AddClaim();
        return result;
    }

    public override Task SignInAsync(FantasyCriticUser user, bool isPersistent, string? authenticationMethod = null)
    {
        var result = base.SignInAsync(user, isPersistent, authenticationMethod);
        AddClaim();
        return result;
    }

    public override Task SignInAsync(FantasyCriticUser user, AuthenticationProperties authenticationProperties, string? authenticationMethod = null)
    {
        var result = base.SignInAsync(user, authenticationProperties, authenticationMethod);
        AddClaim();
        return result;
    }

    public override Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        var result = base.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient);
        AddClaim();
        return result;
    }

    public override Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)
    {
        var result = base.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
        AddClaim();
        return result;
    }

    private void AddClaim()
    {
        var identity = _contextAccessor.HttpContext?.User.Identities.FirstOrDefault();
        if (identity is null)
        {
            return;
        }

        var existingClaim = identity.Claims.Any(x => x.Type == "scope" && x.Value == IdentityServerConstants.LocalApi.ScopeName);
        if (existingClaim)
        {
            return;
        }

        identity.AddClaim(new Claim("scope", IdentityServerConstants.LocalApi.ScopeName));
    }
}
