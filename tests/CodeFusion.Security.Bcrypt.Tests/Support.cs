using System;
using System.Text;
using FsCheck;
using FsCheck.Fluent;

namespace CodeFusion.Security.Tests;

static unsafe class Support
{
    /// <summary>The hash of "password123" from Go's golang.org/x/crypto/bcrypt.</summary>
    public const string GoHash = "$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq";

    static readonly UTF8Encoding Strict = new(false, true);

    /// <summary>Any text BCrypt.Net-Next takes as a bcrypt key: valid UTF-16, at most 72 UTF-8 bytes, NULs included.</summary>
    public static Arbitrary<string> Passwords() => ArbMap.Default.ArbFor<string>().Filter(Fits);

    public static bool Fits(string? s)
    {
        if (s is null) return false;
        try { return Strict.GetByteCount(s) <= Bcrypt.MaxPasswordBytes; }
        catch (EncoderFallbackException) { return false; }
    }

    public static Gen<byte[]> Salts() => Gen.ArrayOf(ArbMap.Default.GeneratorFor<byte>(), Bcrypt.SaltBytes);

    /// <summary>"$2b$" settings for BCrypt.Net-Next with this cost and salt.</summary>
    public static string Settings(int cost, byte[] salt, char revision = 'b')
    {
        Span<char> s = stackalloc char[29];
        return new string(s[..Bcrypt.WriteSettings(s, revision, cost, salt)]);
    }

    /// <summary>Runs <paramref name="action"/> on this thread with the loop's offsets form (1) or base-pointer form (2),
    /// whatever this machine would pick.</summary>
    public static T WithForm<T>(int form, Func<T> action)
    {
        Bcrypt.FormOverride = (Bcrypt.LoopForm)form;
        try { return action(); }
        finally { Bcrypt.FormOverride = Bcrypt.LoopForm.Auto; }
    }

    /// <summary>Hashes run together as one interleaved run of <c>items.Length</c> lanes.</summary>
    public static string[] HashTogether((string Password, byte[] Salt, int Cost)[] items)
    {
        Bcrypt.Input* inputs = stackalloc Bcrypt.Input[items.Length];
        uint* ct = stackalloc uint[6 * items.Length];
        for (int i = 0; i < items.Length; i++)
            if (!Bcrypt.Prepare(items[i].Password, items[i].Salt, items[i].Cost, 'b', BcryptPrehash.None, inputs + i))
                throw new ArgumentException("unusable password", nameof(items));
        Bcrypt.Run(inputs, items.Length, ct);
        var hashes = new string[items.Length];
        for (int i = 0; i < items.Length; i++) hashes[i] = Bcrypt.Format(inputs + i, ct + 6 * i);
        return hashes;
    }
}
