namespace CodeFusion.Security;

/// <summary>What <see cref="BcryptQueue.TryVerifyAsync"/> and <see cref="BcryptQueue.TryHashAsync"/> report.</summary>
public enum BcryptStatus
{
    /// <summary>The password doesn't match, the hash is malformed, or the password is over 72 bytes. Also the
    /// <c>default</c>, so an unset status never reads as a match.</summary>
    NoMatch,

    /// <summary>The password matches the hash.</summary>
    Match,

    /// <summary>The new hash is made: it is in <see cref="BcryptHashResult.Hash"/>.</summary>
    Hashed,

    /// <summary>The queue was full, so nothing was queued: answer 503, say.</summary>
    Busy,

    /// <summary>The token fired before a worker took the call, so it never ran.</summary>
    Cancelled,
}
