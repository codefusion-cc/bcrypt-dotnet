using System;
using System.Linq;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Xunit;
using static CodeFusion.Security.Tests.Support;

namespace CodeFusion.Security.Tests;

/// <summary>The byte overloads of <see cref="Bcrypt"/>, checked against the string ones and BCrypt.Net-Next.</summary>
public class Utf8Tests
{
    static readonly string Hash4 = Bcrypt.Hash("password123", 4);

    static byte[] Ascii(string hash) => Encoding.ASCII.GetBytes(hash);

    static string HashOf(ReadOnlySpan<byte> password, int cost)
    {
        Span<byte> destination = stackalloc byte[Bcrypt.HashLength];
        int written = Bcrypt.Hash(password, cost, destination);
        Assert.Equal(Bcrypt.HashLength, written);
        return Encoding.ASCII.GetString(destination);
    }

    /// <summary>Text at the edges: empty, exactly 72 bytes, 73, a four-byte character ending at byte 72 or 73, NULs.</summary>
    public static TheoryData<string> Edges => new()
    {
        "",
        "\0",
        "a\0b",
        new string('a', 72),
        new string('a', 73),
        new string('a', 68) + "😀", // 72 bytes
        new string('a', 69) + "😀", // 73 bytes
        new string('é', 36), // 72 bytes in 36 characters
        new string('é', 36) + "x",
        "pässwörd €",
    };

    [Theory]
    [MemberData(nameof(Edges))]
    public void VerifyAgreesWithTheStringOverload(string password)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(password);
        bool fits = utf8.Length <= Bcrypt.MaxPasswordBytes;
        Assert.Equal(fits, Bcrypt.PasswordFits(password));
        foreach (char revision in "aby")
        {
            // A hash of the text cut to 72 bytes, as other libraries would make it: a longer password must still fail.
            string hash = BCrypt.Net.BCrypt.HashPassword(password, Settings(4, new byte[16], revision));
            Assert.Equal(Bcrypt.Verify(password, hash), Bcrypt.Verify(utf8, Ascii(hash)));
            Assert.Equal(fits, Bcrypt.Verify(utf8, Ascii(hash)));
            Assert.False(Bcrypt.Verify([.. utf8, (byte)'!'], Ascii(hash)));
        }
    }

    [Theory]
    [MemberData(nameof(Edges))]
    public void HashMakesWhatTheStringOverloadsAndBCryptNetNextCheck(string password)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(password);
        if (utf8.Length > Bcrypt.MaxPasswordBytes)
        {
            Assert.Throws<ArgumentException>(() => Bcrypt.Hash(password, 4));
            var ex = Assert.Throws<ArgumentException>(() => Bcrypt.Hash(utf8, 4, new byte[60]));
            Assert.Equal("passwordUtf8", ex.ParamName);
            return;
        }
        string hash = HashOf(utf8, 5);
        Assert.StartsWith("$2b$05$", hash, StringComparison.Ordinal);
        Assert.True(Bcrypt.Verify(password, hash));
        Assert.True(BCrypt.Net.BCrypt.Verify(password, hash));
        Assert.False(Bcrypt.Verify(password + "!", hash));
    }

    [Property(MaxTest = 40)]
    public Property AnyPasswordGivesTheStringOverloadsAnswers() => Prop.ForAll(
        Passwords(),
        Gen.Zip(Salts(), Gen.Elements('a', 'b', 'y')).ToArbitrary(),
        (password, t) =>
        {
            var (salt, revision) = t;
            byte[] utf8 = Encoding.UTF8.GetBytes(password);
            string hash = Bcrypt.HashWith(password, salt, 4, revision, BcryptPrehash.None);
            byte[] ascii = Ascii(hash);
            bool other = Bcrypt.Verify(password + "x", hash);
            return Bcrypt.Verify(utf8, ascii)
                && Bcrypt.Verify(password, hash)
                && Bcrypt.Verify([.. utf8, (byte)'x'], ascii) == other
                && Bcrypt.Verify(password, HashOf(utf8, 4));
        });

    [Theory]
    [MemberData(nameof(TestVectorTests.Utf8), MemberType = typeof(TestVectorTests))]
    public void VerifiesUtf8Vectors(string password, string hash)
    {
        Assert.True(Bcrypt.Verify(Encoding.UTF8.GetBytes(password), Ascii(hash)));
        Assert.False(Bcrypt.Verify(Encoding.UTF8.GetBytes(password + "x"), Ascii(hash)));
    }

    /// <summary>Bytes that aren't UTF-8 are the key as they are, as in OpenBSD and Openwall: no string can carry them.</summary>
    [Theory]
    [MemberData(nameof(TestVectorTests.NotUtf8), MemberType = typeof(TestVectorTests))]
    [MemberData(nameof(TestVectorTests.Openwall), MemberType = typeof(TestVectorTests))]
    public void VerifiesVectorsWhosePasswordsAreBytes(byte[] password, string hash) =>
        Assert.Equal(password.Length <= Bcrypt.MaxPasswordBytes, Bcrypt.Verify(password, Ascii(hash)));

    public static TheoryData<string> Malformed => new()
    {
        "",
        "malformed",
        "$2b$04$nope",
        Hash4[..^1], // one character short
        Hash4 + ".", // one too many
        Hash4[..29], // settings only
        Hash4.Replace("$2b$", "$2x$", StringComparison.Ordinal),
        Hash4.Replace("$04$", "$03$", StringComparison.Ordinal),
        Hash4.Replace("$04$", "$32$", StringComparison.Ordinal),
        BcryptQueueTests.StrayChecksumBits(Hash4),
        Hash4[..40] + "!" + Hash4[41..], // a character outside the alphabet
    };

    [Theory]
    [MemberData(nameof(Malformed))]
    public void AMalformedHashIsFalse(string hash)
    {
        Assert.False(Bcrypt.Verify("password123", hash));
        Assert.False(Bcrypt.Verify("password123"u8, Ascii(hash)));
    }

    /// <summary>A byte past ASCII is no hash character, though widened to a char it is one of Latin-1's.</summary>
    [Fact]
    public void ABytePastAsciiIsNotAHashCharacter()
    {
        byte[] hash = Ascii(Hash4);
        Assert.True(Bcrypt.Verify("password123"u8, hash));
        foreach (int at in new[] { 0, 3, 5, 10, 40, 59 })
        {
            byte[] bad = (byte[])hash.Clone();
            bad[at] = 0xC3;
            Assert.False(Bcrypt.Verify("password123"u8, bad));
        }
        Assert.False(Bcrypt.Verify("password123"u8, [.. hash, 0]));
        Assert.False(Bcrypt.Verify("password123"u8, new byte[1000]));
    }

    /// <summary>The original "$2$" revision, 59 characters and no terminating NUL in the key.</summary>
    [Fact]
    public void ChecksTheOriginalRevision()
    {
        string ours = Bcrypt.Hash("U*U*", "$2$05$CCCCCCCCCCCCCCCCCCCCC.");
        Assert.Equal(59, ours.Length);
        Assert.True(Bcrypt.Verify("U*U*", ours));
        Assert.True(Bcrypt.Verify("U*U*"u8, Ascii(ours)));
        Assert.False(Bcrypt.Verify("U*U*\0"u8, Ascii(ours)));
    }

    [Fact]
    public void HashRefusesBadArguments()
    {
        Assert.Throws<ArgumentException>(() => Bcrypt.Hash("x"u8, 4, new byte[59]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.Hash("x"u8, 3, new byte[60]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.Hash("x"u8, 32, new byte[60]));
        Assert.Throws<ArgumentException>(() => Bcrypt.Hash(new byte[73], 4, new byte[60]));
    }

    /// <summary>A destination longer than the hash keeps its bytes past it.</summary>
    [Fact]
    public void HashWritesOnlyItsSixtyBytes()
    {
        var destination = Enumerable.Repeat((byte)0xEE, 64).ToArray();
        Assert.Equal(60, Bcrypt.Hash("x"u8, 4, destination));
        Assert.All(destination[60..], b => Assert.Equal(0xEE, b));
        Assert.True(Bcrypt.Verify("x", Encoding.ASCII.GetString(destination, 0, 60)));
    }

    [Fact]
    public void TwoHashesOfOnePasswordDiffer() => Assert.NotEqual(HashOf("x"u8, 4), HashOf("x"u8, 4));
}
