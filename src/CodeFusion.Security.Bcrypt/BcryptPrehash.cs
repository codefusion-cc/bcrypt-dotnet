namespace CodeFusion.Security;

/// <summary>
/// How an enhanced hash digests the password before bcrypt: the key is the base64 of this SHA-2 digest, as in
/// BCrypt.Net-Next's HashType. A digest fits bcrypt's 72 bytes, so passwords of any length count in full.
/// </summary>
public enum BcryptPrehash
{
    /// <summary>Plain bcrypt: the password itself is the key.</summary>
    None = 0,

    /// <summary>SHA-256.</summary>
    Sha256 = 1,

    /// <summary>SHA-384, BCrypt.Net-Next's default.</summary>
    Sha384 = 2,

    /// <summary>SHA-512. Its 88 base64 characters are cut to bcrypt's 72 bytes.</summary>
    Sha512 = 3,
}
