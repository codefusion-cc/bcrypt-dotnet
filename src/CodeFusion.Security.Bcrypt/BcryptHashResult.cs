using System;

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

    /// <summary>Copies the new hash's <see cref="Bcrypt.HashLength"/> ASCII bytes to the start of
    /// <paramref name="destination"/>.</summary>
    /// <exception cref="InvalidOperationException">There is no hash: <see cref="Status"/> is Busy or Cancelled.</exception>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is too short.</exception>
    public void CopyTo(Span<byte> destination)
    {
        if (Status != BcryptStatus.Hashed) throw new InvalidOperationException($"there is no hash: the call was {Status}");
        Hash.CopyTo(destination);
    }
}
