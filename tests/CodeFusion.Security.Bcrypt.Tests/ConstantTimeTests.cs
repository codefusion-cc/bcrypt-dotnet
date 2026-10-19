using System;
using System.Diagnostics;
using System.Linq;
using Xunit;

namespace CodeFusion.Security.Tests;

/// <summary>
/// The check of a computed hash against the stored one takes as long wherever they first differ. The same timing
/// run over an early-exit comparison of the same work shows the run can see such a difference.
/// </summary>
[Collection(nameof(Measuring))]
public unsafe class ConstantTimeTests
{
    const int Rounds = 61, PerRound = 20_000;

    [Fact]
    public void CheckTakesAsLongWhereverTheHashesDiffer()
    {
        string hash = Bcrypt.Hash("password123", 4);
        uint* ct = stackalloc uint[6];
        Bcrypt.Input input;
        Assert.True(Bcrypt.PrepareVerify("password123", hash, BcryptPrehash.None, &input));
        Bcrypt.Run(&input, 1, ct);

        string stored = hash[^31..];
        string differsFirst = Flip(stored, 0), differsLast = Flip(stored, 29);
        Assert.True(Bcrypt.Matches(ct, stored));
        Assert.False(Bcrypt.Matches(ct, differsFirst));
        Assert.False(Bcrypt.Matches(ct, differsLast));

        uint* c = ct;
        double leaky = RelativeGap(s => EarlyExit(c, s), differsFirst, differsLast);
        double ours = RelativeGap(s => Bcrypt.Matches(c, s), differsFirst, differsLast);
        // On an M1 an early exit measured 9 to 10% and the real check 0.5 to 2%.
        Assert.True(leaky > 0.05, $"the timing can't see an early exit here (gap {leaky:P1}), so it proves nothing");
        Assert.True(ours < leaky / 2, $"the check took {ours:P1} longer or shorter by where the hashes differ; an early exit: {leaky:P1}");
    }

    static string Flip(string s, int i) => s[..i] + (s[i] == 'A' ? 'B' : 'A') + s[(i + 1)..];

    /// <summary>The work of the real check with an ordinary comparison that stops at the first difference.</summary>
    static bool EarlyExit(uint* c, string stored)
    {
        Span<byte> bytes = stackalloc byte[Bcrypt.HashBytes];
        for (int i = 0; i < Bcrypt.HashBytes; i++) bytes[i] = (byte)(c[i / 4] >> (24 - 8 * (i % 4)));
        Span<char> encoded = stackalloc char[31];
        Bcrypt.Encode(bytes, encoded);
        for (int i = 0; i < 31; i++)
            if (encoded[i] != stored[i]) return false;
        return true;
    }

    /// <summary>|median(a) - median(b)| / median(a), timing a and b in alternating rounds so drift hits both.</summary>
    static double RelativeGap(Func<string, bool> check, string a, string b)
    {
        for (int i = 0; i < PerRound; i++) { check(a); check(b); }
        var ta = new double[Rounds];
        var tb = new double[Rounds];
        for (int r = 0; r < Rounds; r++)
        {
            ta[r] = Time(check, a);
            tb[r] = Time(check, b);
        }
        double ma = ta.Order().ElementAt(Rounds / 2), mb = tb.Order().ElementAt(Rounds / 2);
        return Math.Abs(ma - mb) / ma;
    }

    static double Time(Func<string, bool> check, string s)
    {
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < PerRound; i++) check(s);
        return Stopwatch.GetTimestamp() - start;
    }
}
