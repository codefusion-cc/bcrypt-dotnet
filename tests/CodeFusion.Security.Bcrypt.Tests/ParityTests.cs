using System;
using System.Linq;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Xunit;
using static CodeFusion.Security.Tests.Support;
using Net = BCrypt.Net;

namespace CodeFusion.Security.Tests;

/// <summary>Each BCrypt.Net-Next 4.2 feature, checked against BCrypt.Net-Next itself.</summary>
public class ParityTests
{
    public static TheoryData<BcryptPrehash, Net.HashType> Prehashes => new()
    {
        { BcryptPrehash.Sha256, Net.HashType.SHA256 },
        { BcryptPrehash.Sha384, Net.HashType.SHA384 },
        { BcryptPrehash.Sha512, Net.HashType.SHA512 },
    };

    static readonly (BcryptPrehash, Net.HashType)[] Pairs =
        [(BcryptPrehash.Sha256, Net.HashType.SHA256), (BcryptPrehash.Sha384, Net.HashType.SHA384), (BcryptPrehash.Sha512, Net.HashType.SHA512)];

    [Theory]
    [MemberData(nameof(Prehashes))]
    public void EnhancedHashesWorkBothWays(BcryptPrehash ours, Net.HashType theirs)
    {
        string longPassword = string.Concat(Enumerable.Repeat("long pässwörd ", 40)); // 600 bytes: all of it counts
        foreach (string password in new[] { "", "hunter2", longPassword, "\0€😀" })
        {
            string mine = Bcrypt.EnhancedHash(password, 4, ours);
            Assert.StartsWith("$2b$04$", mine);
            Assert.True(Net.BCrypt.EnhancedVerify(password, mine, theirs));
            Assert.True(Bcrypt.EnhancedVerify(password, mine, ours));
            Assert.False(Bcrypt.EnhancedVerify(password + "!", mine, ours));
            Assert.False(Bcrypt.Verify(password, mine)); // a plain check of an enhanced hash fails

            string net = Net.BCrypt.EnhancedHashPassword(password, 4, theirs);
            Assert.True(Bcrypt.EnhancedVerify(password, net, ours));
        }
        Assert.False(Bcrypt.EnhancedVerify(longPassword[..^1], Bcrypt.EnhancedHash(longPassword, 4, ours), ours));
    }

    [Property(MaxTest = 25)]
    public Property EnhancedHashWithTheSameSaltIsBCryptNetNexts() => Prop.ForAll(
        ArbMap.Default.ArbFor<string>().Filter(s => s is not null && Bcrypt.PasswordFits(s[..Math.Min(s.Length, 60)])),
        Gen.Zip(Salts(), Gen.Zip(Gen.Elements('a', 'b', 'y'), Gen.Choose(0, 2))).ToArbitrary(),
        (password, t) =>
        {
            var (salt, (revision, type)) = (t.Item1, (t.Item2.Item1, t.Item2.Item2));
            var (ours, theirs) = Pairs[type];
            string net = Net.BCrypt.HashPassword(password, Settings(4, salt, revision), enhancedEntropy: true, theirs);
            return Bcrypt.HashWith(password, salt, 4, revision, ours) == net;
        });

    /// <summary>Past 16K characters the digest is taken a chunk at a time, including surrogate pairs split at a
    /// chunk's end.</summary>
    [Theory]
    [InlineData(16 * 1024 + 1)]
    [InlineData(100_000)]
    public void EnhancedTakesPasswordsOfAnyLength(int pairs)
    {
        // After the "a", every pair starts at an odd index, so each 16K-character chunk ends inside a pair.
        string password = "a" + string.Concat(Enumerable.Repeat("😀", pairs));
        Assert.True(char.IsHighSurrogate(password[16 * 1024 - 1]));
        string net = Net.BCrypt.EnhancedHashPassword(password, 4);
        Assert.True(Bcrypt.EnhancedVerify(password, net));
        Assert.False(Bcrypt.EnhancedVerify(password[..^1], net));
        Assert.True(Net.BCrypt.EnhancedVerify(password, Bcrypt.EnhancedHash(password, 4)));
        // A high surrogate ending a chunk with no low one after it is refused.
        string broken = password[..(16 * 1024)] + "x" + password[(16 * 1024 + 1)..];
        Assert.False(Bcrypt.EnhancedVerify(broken, net));
        Assert.Throws<ArgumentException>(() => Bcrypt.EnhancedHash(broken, 4));
    }

    [Fact]
    public void AnUnknownPrehashIsRefused()
    {
        string hash = Bcrypt.Hash("old", 4);
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.ValidateAndReplacePassword("old", hash, (BcryptPrehash)7, "new", BcryptPrehash.None, 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.ValidateAndReplacePassword("old", hash, BcryptPrehash.None, "new", (BcryptPrehash)7, 4));
    }

    [Fact]
    public void EnhancedNeedsAPrehash()
    {
        Assert.Throws<ArgumentException>(() => Bcrypt.EnhancedHash("x", 4, BcryptPrehash.None));
        Assert.Throws<ArgumentException>(() => Bcrypt.EnhancedVerify("x", Bcrypt.Hash("x", 4), BcryptPrehash.None));
        Assert.Throws<ArgumentException>(() => Bcrypt.EnhancedHash("x", 4, (BcryptPrehash)99));
    }

    [Fact]
    public void EnhancedRefusesTextThatIsNotValidUtf16() =>
        Assert.Throws<ArgumentException>(() => Bcrypt.EnhancedHash("a\ud800", 4));

    [Theory]
    [InlineData('a')]
    [InlineData('b')]
    [InlineData('y')]
    public void GenerateSaltWorksForBoth(char revision)
    {
        string salt = Bcrypt.GenerateSalt(5, revision);
        Assert.Matches($"^\\$2{revision}\\$05\\$[./A-Za-z0-9]{{22}}$", salt);
        Assert.Contains(salt[^1], ".Oeu"); // the last salt character carries 2 bits, the rest zero
        Assert.Equal(Net.BCrypt.HashPassword("pw", salt), Bcrypt.Hash("pw", salt));
        Assert.NotEqual(salt, Bcrypt.GenerateSalt(5, revision));
    }

    [Theory]
    [InlineData('x')]
    [InlineData('c')]
    [InlineData('$')]
    public void GenerateSaltRefusesOtherRevisions(char revision) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.GenerateSalt(10, revision));

    [Fact]
    public void GenerateSaltDefaultsTo2bAndCost11() => Assert.StartsWith("$2b$11$", Bcrypt.GenerateSalt());

    [Fact]
    public void HashTakesAWholeHashAsItsSalt()
    {
        string hash = Bcrypt.Hash("pw", 4);
        Assert.Equal(hash, Bcrypt.Hash("pw", hash));
    }

    [Theory]
    [InlineData("$2b$04$")]
    [InlineData("$2b$04$abcdefghijklmnopqrstu")] // 21 salt characters
    [InlineData("$2b$04$abcdefghijklmnopqrstuvw")] // 23
    [InlineData("2b$04$abcdefghijklmnopqrstuv")]
    public void HashRefusesAMalformedSalt(string salt)
    {
        var e = Assert.Throws<ArgumentException>(() => Bcrypt.Hash("pw", salt));
        Assert.Equal("salt", e.ParamName);
        Assert.Throws<ArgumentNullException>(() => Bcrypt.Hash("pw", (string)null!));
    }

    /// <summary>
    /// The original "$2$": no NUL after the key. BCrypt.Net-Next computes the same hash but writes its revision as
    /// "$2\0$", so only the 31 hash characters compare.
    /// </summary>
    [Theory]
    [InlineData("password")]
    [InlineData("é")]
    public void OriginalRevisionMatchesBCryptNetNext(string password)
    {
        string salt = "$2$05$" + Bcrypt.GenerateSalt(5)[7..];
        string ours = Bcrypt.Hash(password, salt);
        Assert.Equal(59, ours.Length);
        Assert.StartsWith(salt, ours);
        Assert.Equal(Net.BCrypt.HashPassword(password, salt)[^31..], ours[^31..]);
        Assert.True(Bcrypt.Verify(password, ours));
        Assert.False(Bcrypt.Verify(password + "x", ours));
        Assert.NotEqual(ours[^31..], Bcrypt.Hash(password, "$2a$05$" + salt[6..])[^31..]); // the NUL counts
    }

    /// <summary>An empty "$2$" key reads as zero bytes, as C reads the string's end, the same as "$2a$"'s lone NUL.
    /// BCrypt.Net-Next throws for it.</summary>
    [Fact]
    public void OriginalRevisionTakesAnEmptyPassword()
    {
        string salt = Bcrypt.GenerateSalt(5)[7..];
        string ours = Bcrypt.Hash("", "$2$05$" + salt);
        Assert.True(Bcrypt.Verify("", ours));
        Assert.Equal(Bcrypt.Hash("", "$2a$05$" + salt)[^31..], ours[^31..]);
    }

    [Fact]
    public void PasswordNeedsRehashComparesTheCost()
    {
        string hash = Bcrypt.Hash("x", 5);
        Assert.True(Bcrypt.PasswordNeedsRehash(hash, 6));
        Assert.False(Bcrypt.PasswordNeedsRehash(hash, 5));
        Assert.False(Bcrypt.PasswordNeedsRehash(hash, 4));
        Assert.Equal(Net.BCrypt.PasswordNeedsRehash(GoHash, 11), Bcrypt.PasswordNeedsRehash(GoHash, 11));
        Assert.Throws<FormatException>(() => Bcrypt.PasswordNeedsRehash("nope", 10));
        Assert.Throws<ArgumentNullException>(() => Bcrypt.PasswordNeedsRehash(null!, 10));
    }

    [Theory]
    [InlineData(GoHash)]
    [InlineData("$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq")]
    [InlineData("$2$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    public void InterrogateHashGivesWhatBCryptNetNextDoes(string hash)
    {
        var ours = Bcrypt.InterrogateHash(hash);
        var theirs = Net.BCrypt.InterrogateHash(hash);
        Assert.Equal(theirs.Version, ours.Revision);
        Assert.Equal(int.Parse(theirs.WorkFactor, System.Globalization.CultureInfo.InvariantCulture), ours.Cost);
        Assert.Equal(theirs.RawHash, ours.Salt + ours.Checksum);
        Assert.Equal(22, ours.Salt.Length);
        Assert.Equal(31, ours.Checksum.Length);
        Assert.Equal(theirs.Settings + "$" + ours.Salt, ours.Settings);
        Assert.Equal(hash, ours.Settings + ours.Checksum);
    }

    [Fact]
    public void InterrogateHashRefusesMalformedHashes()
    {
        Assert.Throws<FormatException>(() => Bcrypt.InterrogateHash("$2a$10$tooShort"));
        Assert.False(Bcrypt.TryInterrogateHash("", out var info));
        Assert.Equal(default, info);
    }

    [Fact]
    public void ValidateAndReplacePasswordNeedsTheCurrentPassword()
    {
        string current = Bcrypt.Hash("old", 5);
        Assert.Null(Bcrypt.ValidateAndReplacePassword("wrong", current, "new", 4));
        Assert.Null(Bcrypt.ValidateAndReplacePassword("old", "malformed", "new", 4));

        string? replaced = Bcrypt.ValidateAndReplacePassword("old", current, "new", 4);
        Assert.NotNull(replaced);
        Assert.True(Bcrypt.Verify("new", replaced));
        Assert.StartsWith("$2b$05$", replaced); // never lowers the cost
        Assert.StartsWith("$2b$04$", Bcrypt.ValidateAndReplacePassword("old", current, "new", 4, forceCost: true));
        Assert.StartsWith("$2b$06$", Bcrypt.ValidateAndReplacePassword("old", current, "new", 6));
        // As BCrypt.Net-Next does for the same inputs.
        Assert.StartsWith("$2a$05$", Net.BCrypt.ValidateAndReplacePassword("old", current, "new", 4));
    }

    [Fact]
    public void ValidateAndReplacePasswordMovesBetweenPlainAndEnhanced()
    {
        string plain = Bcrypt.Hash("old", 4);
        string? enhanced = Bcrypt.ValidateAndReplacePassword("old", plain, BcryptPrehash.None, "new", BcryptPrehash.Sha512, 4);
        Assert.NotNull(enhanced);
        Assert.True(Bcrypt.EnhancedVerify("new", enhanced, BcryptPrehash.Sha512));
        Assert.True(Net.BCrypt.EnhancedVerify("new", enhanced, Net.HashType.SHA512));
        Assert.Null(Bcrypt.ValidateAndReplacePassword("old", enhanced, BcryptPrehash.Sha512, "x", BcryptPrehash.None, 4));
        Assert.NotNull(Bcrypt.ValidateAndReplacePassword("new", enhanced, BcryptPrehash.Sha512, "x", BcryptPrehash.None, 4));
    }

    [Fact]
    public void ValidateAndReplacePasswordRefusesBadArguments()
    {
        string current = Bcrypt.Hash("old", 4);
        Assert.Throws<ArgumentNullException>(() => Bcrypt.ValidateAndReplacePassword("old", current, null!, 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.ValidateAndReplacePassword("old", current, "new", 3));
        Assert.Throws<ArgumentException>(() => Bcrypt.ValidateAndReplacePassword("old", current, new string('n', 73), 4));
    }
}
