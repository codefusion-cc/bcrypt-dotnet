namespace CodeFusion.Security;

/// <summary>The parts of a bcrypt hash, from <see cref="Bcrypt.InterrogateHash"/>.</summary>
/// <param name="Revision">"2a", "2b", "2y", or "2" for the original format.</param>
/// <param name="Cost">log2 of the key schedule's rounds, 4 to 31.</param>
/// <param name="Salt">The 22 salt characters.</param>
/// <param name="Checksum">The 31 hash characters after the salt.</param>
public readonly record struct BcryptHashInfo(string Revision, int Cost, string Salt, string Checksum)
{
    /// <summary>"$2b$10$" + salt: what <see cref="Bcrypt.Hash(string, string)"/> takes to hash again with the same salt.</summary>
    public string Settings => "$" + Revision + "$" + Cost.ToString("D2", System.Globalization.CultureInfo.InvariantCulture) + "$" + Salt;
}
