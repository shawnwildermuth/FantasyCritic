using Microsoft.AspNetCore.Identity;

namespace FantasyCritic.Lib.Identity;

public class FantasyCriticUser : IdentityUser<Guid>, IEquatable<FantasyCriticUser>
{
    public FantasyCriticUser()
    {

    }

    public FantasyCriticUser(Guid userID, string displayName, string? patreonDonorNameOverride, int displayNumber, string emailAddress, string normalizedEmailAddress,
        bool emailConfirmed, string securityStamp, string passwordHash, bool twoFactorEnabled, string? authenticatorKey, Instant lastChangedCredentials, bool isDeleted)
    {
        Id = userID;
        UserName = displayName;
        PatreonDonorNameOverride = patreonDonorNameOverride;
        DisplayNumber = displayNumber;
        Email = emailAddress;
        NormalizedEmail = normalizedEmailAddress;
        EmailConfirmed = emailConfirmed;
        SecurityStamp = securityStamp;
        PasswordHash = passwordHash;
        TwoFactorEnabled = twoFactorEnabled;
        AuthenticatorKey = authenticatorKey;
        LastChangedCredentials = lastChangedCredentials;
        IsDeleted = isDeleted;
    }

    public string? PatreonDonorNameOverride { get; }
    public int DisplayNumber { get; set; }
    public Instant LastChangedCredentials { get; set; }
    public bool IsDeleted { get; set; }
    public string? AuthenticatorKey { get; set; }

    public void UpdateLastUsedCredentials(Instant currentInstant)
    {
        LastChangedCredentials = currentInstant;
    }

    public bool Equals(FantasyCriticUser? other)
    {
        if (ReferenceEquals(null, other)) return false;
        if (ReferenceEquals(this, other)) return true;
        return Id.Equals(other.Id);
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(null, obj)) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != this.GetType()) return false;
        return Equals((FantasyCriticUser)obj);
    }

    public override int GetHashCode()
    {
        return Id.GetHashCode();
    }

    public static FantasyCriticUser GetFakeUser()
    {
        return new FantasyCriticUser(Guid.Empty, "<Non-Existent User>", null, 0, "", "", false, "", "", false, null,
            Instant.MinValue, false);
    }
}
