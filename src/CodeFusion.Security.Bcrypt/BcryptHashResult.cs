namespace CodeFusion.Security;

/// <summary>What <see cref="BcryptQueue.TryHashAsync"/> reports: <see cref="Hash"/> holds the new hash when
/// <see cref="Status"/> is <see cref="BcryptStatus.Hashed"/>.</summary>
public readonly struct BcryptHashResult
{
    internal BcryptHashResult(BcryptStatus status, BcryptHash hash)
    {
        Status = status;
        Hash = hash;
    }

    /// <summary><see cref="BcryptStatus.Hashed"/>, <see cref="BcryptStatus.Busy"/> or <see cref="BcryptStatus.Cancelled"/>.</summary>
    public BcryptStatus Status { get; }

    /// <summary>The new hash; <c>default</c> unless <see cref="Status"/> is <see cref="BcryptStatus.Hashed"/>.</summary>
    public BcryptHash Hash { get; }
}
