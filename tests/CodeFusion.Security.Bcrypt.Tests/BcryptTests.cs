using System;
using System.Linq;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Xunit;
using static CodeFusion.Security.Tests.Support;

namespace CodeFusion.Security.Tests;

public class BcryptTests
{
    [Fact]
    public void VerifiesGoHash() => Assert.True(Bcrypt.Verify("password123", GoHash));

    [Theory]
    [InlineData("password12")]
    [InlineData("password1234")]
    [InlineData("Password123")]
    [InlineData("password123\0")]
    [InlineData("")]
    public void RejectsOtherPasswords(string password) => Assert.False(Bcrypt.Verify(password, GoHash));

    [Fact]
    public void HashIs2bAndDiffersEachTime()
    {
        string a = Bcrypt.Hash("hunter2", 4), b = Bcrypt.Hash("hunter2", 4);
        Assert.NotEqual(a, b); // random salts
        Assert.StartsWith("$2b$04$", a);
        Assert.Equal(60, a.Length);
        Assert.True(Bcrypt.Verify("hunter2", a));
        Assert.True(BCrypt.Net.BCrypt.Verify("hunter2", a));
        Assert.False(Bcrypt.Verify("hunter3", a));
    }

    [Fact]
    public void DefaultCostIs11() => Assert.StartsWith("$2b$11$", Bcrypt.Hash("x"));

    [Theory]
    [InlineData(3)]
    [InlineData(32)]
    [InlineData(0)]
    [InlineData(-1)]
    public void CostOutsideTheRangeIsRefused(int cost)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.Hash("x", cost));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.GenerateSalt(cost));
        Assert.Throws<ArgumentOutOfRangeException>(() => Bcrypt.EnhancedHash("x", cost));
    }

    /// <summary>For every lane count and both forms of the loop, each lane's hash is exactly BCrypt.Net-Next's for its
    /// password, salt and cost.</summary>
    [Property(MaxTest = 40)]
    public Property EveryLaneMatchesBCryptNetNext() => Prop.ForAll(
        Gen.Choose(1, Bcrypt.MaxLanes)
            .SelectMany(n => Gen.ArrayOf(
                Gen.Zip(Passwords().Generator, Gen.Zip(Salts(), Gen.Choose(4, 6))).Select(t => (Password: t.Item1, Salt: t.Item2.Item1, Cost: t.Item2.Item2)), n))
            .ToArbitrary(),
        items =>
        {
            string[] offsets = WithForm(1, () => HashTogether(items)), bases = WithForm(2, () => HashTogether(items));
            for (int k = 0; k < items.Length; k++)
            {
                string expected = BCrypt.Net.BCrypt.HashPassword(items[k].Password, Settings(items[k].Cost, items[k].Salt));
                if (offsets[k] != expected || bases[k] != expected) return false;
            }
            return true;
        });

    /// <summary>
    /// Lane k of an n-lane run gives the hash it gets alone, for every n and k, with one cost and with mixed costs
    /// (the cheaper lanes finish first and the run continues without them).
    /// </summary>
    public static TheoryData<int, int> LanesAndForms => new()
    {
        { 1, 1 }, { 2, 1 }, { 3, 1 }, { 4, 1 }, { 5, 1 },
        { 1, 2 }, { 2, 2 }, { 3, 2 }, { 4, 2 }, { 5, 2 },
    };

    /// <param name="lanes">1 to 5.</param>
    /// <param name="form">1: the loop with constant offsets (x64); 2: with a base pointer per S-box (arm64).</param>
    [Theory]
    [MemberData(nameof(LanesAndForms))]
    public void EachLaneOfEachWidthEqualsItsHashAlone(int lanes, int form) => WithForm(form, () =>
    {
        var salt = Enumerable.Range(1, 16).Select(i => (byte)(i * 37)).ToArray();
        foreach (int[] costs in new[] { Enumerable.Repeat(4, lanes).ToArray(), Enumerable.Range(0, lanes).Select(k => 4 + (k * 3 % 3)).ToArray(), Enumerable.Range(0, lanes).Select(k => 6 - k % 3).ToArray() })
        {
            var items = Enumerable.Range(0, lanes).Select(k => ($"pässwörd {k}", salt, costs[k])).ToArray();
            string[] together = HashTogether(items);
            for (int k = 0; k < lanes; k++)
            {
                string expected = BCrypt.Net.BCrypt.HashPassword(items[k].Item1, Settings(costs[k], salt));
                Assert.Equal(expected, together[k]);
                Assert.Equal(expected, HashTogether([items[k]])[0]);
            }
        }
        return true;
    });

    [Fact]
    public void LaneCountOutsideOneToFiveIsRefused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HashTogether([]));
        var six = Enumerable.Repeat(("x", new byte[16], 4), 6).ToArray();
        Assert.Throws<ArgumentOutOfRangeException>(() => HashTogether(six));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(11)]
    public void BatchVerifyFindsEachMismatch(int count)
    {
        for (int bad = 0; bad < count; bad++)
        {
            string[] passwords = Enumerable.Range(0, count).Select(i => i == bad ? "password124" : "password123").ToArray();
            string[] hashes = Enumerable.Repeat(GoHash, count).ToArray();
            var results = new bool[count];
            Bcrypt.Verify(passwords, hashes, results);
            Assert.Equal(Enumerable.Range(0, count).Select(i => i != bad), results);
        }
    }

    [Fact]
    public void BatchVerifyMixesCostsRevisionsAndMalformedHashes()
    {
        string[] hashes =
        [
            Bcrypt.Hash("a", 5), "not a hash", BCrypt.Net.BCrypt.HashPassword("c", BCrypt.Net.BCrypt.GenerateSalt(4, 'y')),
            Bcrypt.Hash("d", 4), GoHash, Bcrypt.Hash("f", 6), Bcrypt.Hash("g", 4),
        ];
        string[] passwords = ["a", "b", "c", "d", "password123", "wrong", new string('g', 73)];
        var results = new bool[hashes.Length];
        results.AsSpan().Fill(true);
        Bcrypt.Verify(passwords, hashes, results);
        Assert.Equal([true, false, true, true, true, false, false], results);
    }

    [Fact]
    public void BatchVerifyOfNothingDoesNothing() => Bcrypt.Verify([], [], []);

    [Fact]
    public void BatchVerifyRefusesSpansOfDifferentLengths()
    {
        Assert.Throws<ArgumentException>(() => Bcrypt.Verify(["a"], ["b", "c"], new bool[1]));
        Assert.Throws<ArgumentException>(() => Bcrypt.Verify(["a"], ["b"], new bool[2]));
        Assert.Throws<ArgumentNullException>(() => Bcrypt.Verify([null!], [GoHash], new bool[1]));
    }

    [Theory]
    [InlineData('a')]
    [InlineData('b')]
    [InlineData('y')]
    public void VerifiesEveryRevision(char revision)
    {
        string hash = BCrypt.Net.BCrypt.HashPassword("päss wörd", BCrypt.Net.BCrypt.GenerateSalt(4, revision));
        Assert.True(Bcrypt.Verify("päss wörd", hash));
        Assert.False(Bcrypt.Verify("pass word", hash));
    }

    [Fact]
    public void SeventyTwoBytesIsTheLimit()
    {
        string ascii72 = new('a', 72), euro24 = string.Concat(Enumerable.Repeat("€", 24)); // 24 x 3 bytes
        Assert.True(Bcrypt.Verify(ascii72, Bcrypt.Hash(ascii72, 4)));
        Assert.True(Bcrypt.Verify(euro24, Bcrypt.Hash(euro24, 4)));
        Assert.True(Bcrypt.PasswordFits(ascii72));
        Assert.False(Bcrypt.PasswordFits(ascii72 + "a"));
        Assert.False(Bcrypt.PasswordFits(euro24 + "€"));
        Assert.False(Bcrypt.PasswordFits(new string('a', 71) + "é")); // 73 bytes: the last character is cut in half
        var e = Assert.Throws<ArgumentException>(() => Bcrypt.Hash(ascii72 + "a", 4));
        Assert.Equal("password", e.ParamName);
        // A longer password never matches, even one whose first 72 bytes do.
        Assert.False(Bcrypt.Verify(ascii72 + "a", Bcrypt.Hash(ascii72, 4)));
    }

    // Built in code: an attribute stores its strings as UTF-8, which turns a lone surrogate into U+FFFD.
    static readonly string[] NotUtf16 = ["\ud800", "a\udc00b", "\udc00\ud800", new string('a', 70) + "\ud800"];

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void TextThatIsNotValidUtf16IsRefused(int index)
    {
        string password = NotUtf16[index];
        Assert.False(Bcrypt.PasswordFits(password));
        Assert.Throws<ArgumentException>(() => Bcrypt.Hash(password, 4));
        // BCrypt.Net-Next would throw; a check is false, as for every other unusable input.
        Assert.False(Bcrypt.Verify(password, Bcrypt.Hash("�", 4)));
    }

    [Fact]
    public void RefusalsSayWhy()
    {
        Assert.Contains("72", Assert.Throws<ArgumentException>(() => Bcrypt.Hash(new string('a', 73), 4)).Message, StringComparison.Ordinal);
        Assert.Contains("surrogate", Assert.Throws<ArgumentException>(() => Bcrypt.Hash("a\ud800", 4)).Message, StringComparison.Ordinal);
        Assert.Contains("surrogate", Assert.Throws<ArgumentException>(() => Bcrypt.EnhancedHash("a\ud800", 4)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BatchVerifyChecksForNullsBeforeAnything()
    {
        bool[] results = [true, true, true];
        Assert.Throws<ArgumentNullException>(() => Bcrypt.Verify(["password123", "password123", null!], [GoHash, GoHash, GoHash], results));
        Assert.Equal([true, true, true], results); // untouched
    }

    [Fact]
    public void NullsAreRefused()
    {
        Assert.Throws<ArgumentNullException>(() => Bcrypt.Hash(null!, 4));
        Assert.Throws<ArgumentNullException>(() => Bcrypt.Verify(null!, GoHash));
        Assert.Throws<ArgumentNullException>(() => Bcrypt.Verify("x", null!));
        Assert.Throws<ArgumentNullException>(() => Bcrypt.PasswordFits(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899w")] // 59 chars
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wqq")] // 61 chars
    [InlineData("$2x$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // PHP's buggy revision
    [InlineData("$3a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")]
    [InlineData("$2a$03$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // cost below 4
    [InlineData("$2a$32$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // cost above 31
    [InlineData("$2a$1a$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")]
    [InlineData("$2a$10#ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")]
    [InlineData("$2a$10$ZSfEoPvlcsj2Xfvs!eK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // '!' in the salt
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK25ém4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // non-ASCII in the salt
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899w!")] // '!' in the hash
    [InlineData("$2$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wqq")] // "$2$" with a 2a's length
    public void MalformedHashesNeverMatch(string hash)
    {
        Assert.False(Bcrypt.Verify("password123", hash));
        Assert.False(Bcrypt.TryInterrogateHash(hash, out _));
    }

    /// <summary>31 characters carry 186 bits for the hash's 184: the last character's low two bits must be zero, as
    /// the salt's unused bits must.</summary>
    [Fact]
    public void StrayChecksumBitsMakeAHashMalformed()
    {
        string hash = Bcrypt.Hash("x", 4), stray = BcryptQueueTests.StrayChecksumBits(hash);
        Assert.True(Bcrypt.TryInterrogateHash(hash, out _));
        Assert.False(Bcrypt.TryInterrogateHash(stray, out _));
        Assert.False(Bcrypt.Verify("x", stray));
        Assert.Throws<FormatException>(() => Bcrypt.PasswordNeedsRehash(stray, 4));
    }

    [Fact]
    public void StrayLowBitsInTheLastCharacterDoNotMatch()
    {
        // 'q' encodes 0b101010 + 2 unused bits; 'r' is the next value, which differs only in the unused bits.
        string altered = GoHash[..^1] + "r";
        Assert.False(Bcrypt.Verify("password123", altered));
    }

    /// <summary>Changing any one character of a valid hash to any other makes it fail, never throw. That includes the
    /// salt's last character, whose low 4 bits are unused: OpenBSD refuses those changes too.</summary>
    [Fact]
    public void EveryOneCharacterChangeFails()
    {
        string hash = Bcrypt.Hash("x", 4);
        const string chars = "$./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!é\0";
        for (int i = 0; i < hash.Length; i++)
            foreach (char c in chars)
            {
                if (c == hash[i]) continue;
                string changed = hash[..i] + c + hash[(i + 1)..];
                if (Bcrypt.TryInterrogateHash(changed, out var info) && info.Cost > 6) continue; // valid, but hours to check
                bool sameHash = i == 2 && c is 'a' or 'y'; // the three revisions hash alike
                Assert.Equal(sameHash, Bcrypt.Verify("x", changed));
            }
    }

    [Property(MaxTest = 300)]
    public Property VerifyNeverThrows() => Prop.ForAll(ArbMap.Default.ArbFor<string>().Filter(s => s is not null), hash =>
    {
        // Random strings, and random strings forced into the right shape.
        string shaped = "$2a$04$" + new string((hash + new string('.', 53)).Take(53).ToArray());
        Bcrypt.Verify("x", hash);
        Bcrypt.Verify(hash, shaped);
        Bcrypt.TryInterrogateHash(hash, out _);
        return true;
    });

    [Property(MaxTest = 30)]
    public Property HashThenVerifyRoundTrips() => Prop.ForAll(Passwords(), password =>
        Bcrypt.Verify(password, Bcrypt.Hash(password, 4)) && !Bcrypt.Verify(password + "\u0001", Bcrypt.Hash(password, 4)));
}
