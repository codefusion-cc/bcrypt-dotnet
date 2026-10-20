using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;

namespace CodeFusion.Security;

/// <summary>
/// A new bcrypt hash as its 60 ASCII bytes, held inline instead of in a string: what
/// <see cref="BcryptQueue.HashAsync(ReadOnlySpan{byte}, int, System.Threading.CancellationToken)"/> returns. Copy it
/// where it is stored with <see cref="CopyTo"/> or <see cref="TryFormat(Span{byte}, out int, ReadOnlySpan{char}, IFormatProvider?)"/>;
/// <see cref="ToString()"/> makes the string.
/// </summary>
public readonly struct BcryptHash : ISpanFormattable, IUtf8SpanFormattable
{
    readonly Buffer _bytes;

    internal BcryptHash(in Buffer bytes) => _bytes = bytes;

    /// <summary><see cref="Bcrypt.HashLength"/>; 0 for <c>default</c>, which holds no hash.</summary>
    public int Length => _bytes[0] == (byte)'$' ? Bcrypt.HashLength : 0;

    /// <summary>The hash's ASCII bytes, read in place.</summary>
    [UnscopedRef]
    public ReadOnlySpan<byte> AsSpan() => ((ReadOnlySpan<byte>)_bytes)[..Length];

    /// <summary>Copies the hash's ASCII bytes to the start of <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than <see cref="Length"/>.</exception>
    public void CopyTo(Span<byte> destination)
    {
        if (!AsSpan().TryCopyTo(destination)) throw new ArgumentException($"the destination must hold {Length} bytes", nameof(destination));
    }

    /// <summary>Writes the hash's ASCII bytes; false, writing nothing, when <paramref name="utf8Destination"/> is too short.</summary>
    public bool TryFormat(Span<byte> utf8Destination, out int bytesWritten, ReadOnlySpan<char> format = default, IFormatProvider? provider = null)
    {
        bytesWritten = AsSpan().TryCopyTo(utf8Destination) ? Length : 0;
        return bytesWritten == Length;
    }

    /// <summary>Writes the hash's characters; false, writing nothing, when <paramref name="destination"/> is too short.</summary>
    public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format = default, IFormatProvider? provider = null)
    {
        charsWritten = 0;
        if (destination.Length < Length) return false;
        charsWritten = Encoding.ASCII.GetChars(AsSpan(), destination);
        return true;
    }

    /// <summary>The hash as a string, "$2b$..."; empty for <c>default</c>.</summary>
    public override string ToString() => Encoding.ASCII.GetString(AsSpan());

    /// <inheritdoc cref="ToString()"/>
    public string ToString(string? format, IFormatProvider? formatProvider) => ToString();

    /// <summary>A hash's bytes, inline.</summary>
    [InlineArray(Bcrypt.HashLength)]
    internal struct Buffer
    {
        byte _first;
    }
}
