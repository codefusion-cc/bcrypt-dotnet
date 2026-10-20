using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;

namespace CodeFusion.Security;

/// <summary>
/// bcrypt (Provos and Mazières; OpenBSD's bcrypt.c): makes "$2b$" hashes and checks "$2a$", "$2b$", "$2y$" and
/// "$2$" ones. Hashing allocates only the returned string, checking allocates nothing.
/// <para>
/// bcrypt reads at most 72 bytes of a password. Longer passwords are refused rather than silently cut:
/// <see cref="Hash(string, int)"/> throws and <see cref="Verify(string, string)"/> returns false. To accept any
/// length, use <see cref="EnhancedHash"/>, which hashes the password with SHA-2 first.
/// </para>
/// <para>
/// To hash many passwords at once, for example on a server's sign-in path, use <see cref="BcryptQueue"/>: it runs up
/// to five hashes interleaved on one thread, each for about a quarter of the CPU time of one hash alone.
/// </para>
/// </summary>
public static unsafe partial class Bcrypt
{
    /// <summary>The lowest cost (log2 of the rounds) accepted.</summary>
    public const int MinCost = 4;

    /// <summary>The highest cost accepted.</summary>
    public const int MaxCost = 31;

    /// <summary>The cost used when none is given, as in BCrypt.Net-Next.</summary>
    public const int DefaultCost = 11;

    /// <summary>The longest password, in UTF-8 bytes, that bcrypt reads in full.</summary>
    public const int MaxPasswordBytes = 72;

    /// <summary>The length of a hash this library makes, in characters or ASCII bytes: "$2b$", the cost, "$", 22 salt
    /// characters and 31 hash characters.</summary>
    public const int HashLength = 60;

    /// <summary>A new "$2b$" hash of <paramref name="password"/> with a random salt.</summary>
    /// <exception cref="ArgumentException">The password is over 72 UTF-8 bytes or isn't valid UTF-16.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="cost"/> is outside 4 to 31.</exception>
    public static string Hash(string password, int cost = DefaultCost) => Hash(password, cost, BcryptPrehash.None);

    /// <summary>
    /// A new "$2b$" hash of the password in <paramref name="passwordUtf8"/>, written to <paramref name="destination"/>
    /// as ASCII. Allocates nothing. The bytes are the key as they are: UTF-8 gives the hash
    /// <see cref="Hash(string, int)"/> gives the same text, and other bytes are taken too, as OpenBSD and Go take them.
    /// </summary>
    /// <returns>The bytes written: <see cref="HashLength"/>.</returns>
    /// <exception cref="ArgumentException">The password is over 72 bytes, or <paramref name="destination"/> is shorter
    /// than <see cref="HashLength"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="cost"/> is outside 4 to 31.</exception>
    public static int Hash(ReadOnlySpan<byte> passwordUtf8, int cost, Span<byte> destination)
    {
        CheckCost(cost);
        if (destination.Length < HashLength) throw new ArgumentException($"the destination must hold {HashLength} bytes", nameof(destination));
        Input input;
        Span<byte> salt = stackalloc byte[SaltBytes];
        RandomNumberGenerator.Fill(salt);
        if (!Prepare(passwordUtf8, salt, cost, 'b', &input)) throw new ArgumentException(TooLong, nameof(passwordUtf8));
        uint* ct = stackalloc uint[6];
        Run(&input, 1, ct);
        int written = Format(&input, ct, destination);
        Wipe(&input, 1);
        return written;
    }

    /// <summary>
    /// The hash of <paramref name="password"/> with the revision, cost and salt of <paramref name="salt"/>: a value
    /// from <see cref="GenerateSalt"/>, or a whole hash.
    /// </summary>
    /// <exception cref="ArgumentException">The password is over 72 UTF-8 bytes or isn't valid UTF-16, or the salt is malformed.</exception>
    public static string Hash(string password, string salt) => HashWithSalt(password, salt, BcryptPrehash.None);

    /// <summary>Whether <paramref name="password"/> matches <paramref name="hash"/>. A malformed hash, or a password
    /// over 72 UTF-8 bytes or not valid UTF-16, never matches. Never throws for any non-null input.</summary>
    public static bool Verify(string password, string hash) => Verify(password, hash, BcryptPrehash.None);

    /// <summary>
    /// Whether the password in <paramref name="passwordUtf8"/> matches <paramref name="hash"/>, its ASCII bytes. As
    /// <see cref="Verify(string, string)"/> for the UTF-8 of the same text; other bytes are taken as they are. A
    /// malformed hash, or a password over 72 bytes, never matches. Allocates nothing and never throws.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> passwordUtf8, ReadOnlySpan<byte> hash)
    {
        Input input;
        if (!PrepareVerify(passwordUtf8, hash, &input)) return false;
        uint* ct = stackalloc uint[6];
        Run(&input, 1, ct);
        Wipe(&input, 1);
        return Matches(ct, hash[^HashChars..]);
    }

    /// <summary>
    /// Checks <c>passwords[i]</c> against <c>hashes[i]</c> into <c>results[i]</c>, up to five at a time interleaved on
    /// this thread: five checks take 1.3 to 2 times as long as one, depending on the CPU.
    /// </summary>
    /// <exception cref="ArgumentException">The spans' lengths differ.</exception>
    public static void Verify(ReadOnlySpan<string> passwords, ReadOnlySpan<string> hashes, Span<bool> results)
    {
        if (hashes.Length != passwords.Length || results.Length != passwords.Length)
            throw new ArgumentException("passwords, hashes and results must have the same length", nameof(results));
        for (int i = 0; i < passwords.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(passwords[i], nameof(passwords));
            ArgumentNullException.ThrowIfNull(hashes[i], nameof(hashes));
        }
        Input* inputs = stackalloc Input[MaxLanes];
        int* index = stackalloc int[MaxLanes];
        uint* ct = stackalloc uint[6 * MaxLanes];
        int n = 0;
        for (int i = 0; i < passwords.Length; i++)
        {
            results[i] = false;
            if (PrepareVerify(passwords[i], hashes[i], BcryptPrehash.None, inputs + n)) index[n++] = i;
            if (n == MaxLanes || (i == passwords.Length - 1 && n > 0))
            {
                Run(inputs, n, ct);
                for (int k = 0; k < n; k++)
                {
                    string hash = hashes[index[k]];
                    results[index[k]] = Matches(ct + 6 * k, hash.AsSpan(hash.Length - HashChars));
                }
                n = 0;
            }
        }
        Wipe(inputs, MaxLanes);
    }

    /// <summary>
    /// A new "$2b$" hash of the SHA-2 digest of <paramref name="password"/>, so any length counts in full. Compatible
    /// with BCrypt.Net-Next's EnhancedHashPassword; check it with <see cref="EnhancedVerify"/> and the same
    /// <paramref name="prehash"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The password isn't valid UTF-16, or <paramref name="prehash"/> is None.</exception>
    public static string EnhancedHash(string password, int cost = DefaultCost, BcryptPrehash prehash = BcryptPrehash.Sha384) =>
        Hash(password, cost, RequirePrehash(prehash));

    /// <summary>Whether <paramref name="password"/> matches a hash from <see cref="EnhancedHash"/> (or BCrypt.Net-Next's
    /// EnhancedHashPassword) made with the same <paramref name="prehash"/>.</summary>
    public static bool EnhancedVerify(string password, string hash, BcryptPrehash prehash = BcryptPrehash.Sha384) =>
        Verify(password, hash, RequirePrehash(prehash));

    /// <summary>"$2b$" + two-digit cost + "$" + 22 random salt characters, for <see cref="Hash(string, string)"/>.</summary>
    /// <param name="cost">4 to 31.</param>
    /// <param name="revision">'a', 'b' or 'y'. All three hash identically for passwords up to 72 bytes.</param>
    public static string GenerateSalt(int cost = DefaultCost, char revision = 'b')
    {
        CheckCost(cost);
        if (revision is not ('a' or 'b' or 'y')) throw new ArgumentOutOfRangeException(nameof(revision), revision, "the revision must be 'a', 'b' or 'y'");
        Span<byte> salt = stackalloc byte[SaltBytes];
        RandomNumberGenerator.Fill(salt);
        Span<char> s = stackalloc char[29];
        return new string(s[..WriteSettings(s, revision, cost, salt)]);
    }

    /// <summary>Whether <paramref name="hash"/> was made with a cost below <paramref name="minimumCost"/>, so it should
    /// be replaced at the next successful sign-in.</summary>
    /// <exception cref="FormatException">The hash is malformed.</exception>
    public static bool PasswordNeedsRehash(string hash, int minimumCost) => InterrogateHash(hash).Cost < minimumCost;

    /// <summary>The parts of <paramref name="hash"/>.</summary>
    /// <exception cref="FormatException">The hash is malformed.</exception>
    public static BcryptHashInfo InterrogateHash(string hash) =>
        TryInterrogateHash(hash, out var info) ? info : throw new FormatException("not a bcrypt hash");

    /// <summary>The parts of <paramref name="hash"/>; false when it's malformed.</summary>
    public static bool TryInterrogateHash(string hash, out BcryptHashInfo info)
    {
        ArgumentNullException.ThrowIfNull(hash);
        info = default;
        Span<byte> salt = stackalloc byte[SaltBytes];
        int end = ParseSettings(hash, out char revision, out int cost, salt);
        if (!IsWholeHash(hash, end)) return false;
        info = new BcryptHashInfo(revision == '\0' ? "2" : "2" + revision, cost, hash.Substring(end - SaltChars, SaltChars), hash[end..]);
        return true;
    }

    /// <summary>
    /// A new hash of <paramref name="newPassword"/> if <paramref name="currentPassword"/> matches
    /// <paramref name="currentHash"/>, else null. The new hash keeps the current hash's cost when that is higher than
    /// <paramref name="cost"/>, unless <paramref name="forceCost"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The new password is over 72 UTF-8 bytes or isn't valid UTF-16.</exception>
    public static string? ValidateAndReplacePassword(string currentPassword, string currentHash, string newPassword, int cost = DefaultCost, bool forceCost = false) =>
        ValidateAndReplacePassword(currentPassword, currentHash, BcryptPrehash.None, newPassword, BcryptPrehash.None, cost, forceCost);

    /// <summary>
    /// <see cref="ValidateAndReplacePassword(string, string, string, int, bool)"/> where either hash may be an enhanced
    /// one: <paramref name="currentPrehash"/> and <paramref name="newPrehash"/> are None for plain bcrypt.
    /// </summary>
    public static string? ValidateAndReplacePassword(string currentPassword, string currentHash, BcryptPrehash currentPrehash,
        string newPassword, BcryptPrehash newPrehash, int cost = DefaultCost, bool forceCost = false)
    {
        ArgumentNullException.ThrowIfNull(newPassword);
        CheckCost(cost);
        CheckPrehash(currentPrehash);
        CheckPrehash(newPrehash);
        if (!Verify(currentPassword, currentHash, currentPrehash)) return null;
        if (!forceCost && TryInterrogateHash(currentHash, out var current) && current.Cost > cost) cost = current.Cost;
        return Hash(newPassword, cost, newPrehash);
    }

    /// <summary>Whether <see cref="Hash(string, int)"/> accepts <paramref name="password"/>: at most 72 UTF-8 bytes and
    /// valid UTF-16. Check it when a password is chosen, to tell the user rather than fail.</summary>
    public static bool PasswordFits(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        Span<byte> key = stackalloc byte[MaxPasswordBytes];
        bool fits = Utf8.FromUtf16(password, key, out _, out _, replaceInvalidSequences: false) == System.Buffers.OperationStatus.Done;
        CryptographicOperations.ZeroMemory(key);
        return fits;
    }

    // ---------- shared by the overloads ----------

    internal static string Hash(string password, int cost, BcryptPrehash prehash)
    {
        ArgumentNullException.ThrowIfNull(password);
        CheckCost(cost);
        Span<byte> salt = stackalloc byte[SaltBytes];
        RandomNumberGenerator.Fill(salt);
        return HashWith(password, salt, cost, 'b', prehash);
    }

    static string HashWithSalt(string password, string salt, BcryptPrehash prehash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        Span<byte> bytes = stackalloc byte[SaltBytes];
        int end = ParseSettings(salt, out char revision, out int cost, bytes);
        if (end < 0 || (salt.Length != end && salt.Length != end + HashChars))
            throw new ArgumentException("not a bcrypt salt: expected \"$2b$\", a cost of 04 to 31, \"$\" and 22 salt characters", nameof(salt));
        return HashWith(password, bytes, cost, revision, prehash);
    }

    internal static string HashWith(string password, ReadOnlySpan<byte> salt, int cost, char revision, BcryptPrehash prehash)
    {
        Input input;
        CheckPrehash(prehash);
        if (!Prepare(password, salt, cost, revision, prehash, &input)) throw new ArgumentException(RefusalOf(password), nameof(password));
        uint* ct = stackalloc uint[6];
        Run(&input, 1, ct);
        string hash = Format(&input, ct);
        Wipe(&input, 1);
        return hash;
    }

    internal static bool Verify(string password, string hash, BcryptPrehash prehash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hash);
        CheckPrehash(prehash);
        Input input;
        if (!PrepareVerify(password, hash, prehash, &input)) return false;
        uint* ct = stackalloc uint[6];
        Run(&input, 1, ct);
        Wipe(&input, 1);
        return Matches(ct, hash.AsSpan(hash.Length - HashChars));
    }

    internal static void CheckCost(int cost)
    {
        if (cost is < MinCost or > MaxCost) throw new ArgumentOutOfRangeException(nameof(cost), cost, "the cost must be 4 to 31");
    }

    static BcryptPrehash RequirePrehash(BcryptPrehash prehash) => prehash is BcryptPrehash.Sha256 or BcryptPrehash.Sha384 or BcryptPrehash.Sha512
        ? prehash
        : throw new ArgumentException("an enhanced hash needs Sha256, Sha384 or Sha512", nameof(prehash));
}
