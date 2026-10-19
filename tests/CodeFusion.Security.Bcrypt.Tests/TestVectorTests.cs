using System;
using System.Linq;
using Xunit;

namespace CodeFusion.Security.Tests;

/// <summary>
/// Published bcrypt test vectors: pyca/bcrypt's (which include OpenBSD's) and Openwall crypt_blowfish 1.3's
/// wrapper.c, including its "$2x$" and "$2y$" cases for bytes with the high bit set.
/// </summary>
public class TestVectorTests
{
    /// <summary>The tables the generator computes are pi's hex digits, as Schneier published them for Blowfish.</summary>
    [Fact]
    public void BlowfishTablesAreTheDigitsOfPi()
    {
        Assert.Equal(18, BlowfishConstants.P.Length);
        Assert.Equal(1024, BlowfishConstants.S.Length);
        Assert.Equal(0x243f6a88u, BlowfishConstants.P[0]);
        Assert.Equal(0x8979fb1bu, BlowfishConstants.P[17]);
        Assert.Equal(0xd1310ba6u, BlowfishConstants.S[0]);
        Assert.Equal(0x3ac372e6u, BlowfishConstants.S[1023]);
    }

    [Theory]
    [MemberData(nameof(Utf8))]
    public void VerifiesAndReproducesUtf8Vectors(string password, string hash)
    {
        Assert.True(Bcrypt.Verify(password, hash));
        Assert.Equal(hash, Bcrypt.Hash(password, hash[..29]));
        Assert.False(Bcrypt.Verify(password + "x", hash));
    }

    [Theory]
    [MemberData(nameof(NotUtf8))]
    public void ReproducesVectorsWhosePasswordsAreNotUtf8(byte[] password, string hash) =>
        Assert.Equal(hash, Bcrypt.HashRawKey(password, hash[..29]));

    public static TheoryData<byte[], string> Openwall => new()
    {
        { [0xa3], "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq" },
        { [0xa3], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq" },
        { [0xa3], "$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq" },
        { [0xff, 0xff, 0xa3], "$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e" },
        { [0xff, 0xff, 0xa3], "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e" },
        { [0xff, 0xa3, .. "34"u8, 0xff, 0xff, 0xff, 0xa3, .. "345"u8], "$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi" },
        { [0xff, 0xa3, .. "345"u8], "$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e" },
        { [0xff, 0xa3, .. "345"u8], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e" },
        { [0xa3, .. "ab"u8], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS" },
        { [0xa3, .. "ab"u8], "$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS" },
        { [.. Enumerable.Repeat((byte)0xaa, 72), .. "chars after 72 are ignored as usual"u8], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6" },
        { [.. Enumerable.Repeat<byte[]>([0xaa, 0x55], 36).SelectMany(b => b)], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy" },
        { [.. Enumerable.Repeat<byte[]>([0x55, 0xaa, 0xff], 24).SelectMany(b => b)], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe" },
        { "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored"u8.ToArray(), "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui" },
        { [], "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy" },
    };

    [Theory]
    [MemberData(nameof(Openwall))]
    public void ReproducesOpenwallVectors(byte[] password, string hash) =>
        Assert.Equal(hash, Bcrypt.HashRawKey(password, hash[..29]));

    /// <summary>
    /// Openwall's "$2a$" adds a countermeasure for the sign-extension bug that changes these two hashes. OpenBSD's
    /// "$2a$", which this library and BCrypt.Net-Next follow, gives the "$2b$" and "$2y$" result instead.
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0xff, 0xff, 0xa3 }, "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85.", "CE5elHaaO4EbggVDjb8P19RukzXSM3e")]
    [InlineData(new byte[] { 0xff, 0xa3, 0x33, 0x34, 0xff, 0xff, 0xff, 0xa3, 0x33, 0x34, 0x35 }, "$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd.", "o./n25XVfn6oAPaUvHe.Csk4zRfsYPi")]
    public void FollowsOpenBsdWhereOpenwallsCountermeasureDiffers(byte[] password, string openwall, string openBsd)
    {
        string ours = Bcrypt.HashRawKey(password, openwall[..29]);
        Assert.NotEqual(openwall, ours);
        Assert.Equal(openwall[..29] + openBsd, ours);
    }

    [Theory]
    [InlineData("$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e")] // "\xa3" and "\xff\xff\xa3"
    [InlineData("$2x$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS")] // "\xa3ab"
    [InlineData("$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS")] // "\xd1\x91", which is "ё"
    public void RefusesPhpsBuggyRevision(string hash)
    {
        Assert.False(Bcrypt.Verify("ё", hash));
        Assert.False(Bcrypt.TryInterrogateHash(hash, out _));
        Assert.Throws<ArgumentException>(() => Bcrypt.Hash("ё", hash));
    }

    /// <summary>Openwall's settings that must be refused.</summary>
    [Theory]
    [InlineData("$2a$03$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("$2a$32$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("$2c$05$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("$2z$05$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("$2`$05$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("$2{$05$CCCCCCCCCCCCCCCCCCCCC.")]
    public void RefusesBadSettings(string settings)
    {
        Assert.Throws<ArgumentException>(() => Bcrypt.Hash("", settings));
        Assert.False(Bcrypt.Verify("", settings + "7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"));
    }

    [Fact]
    public void RefusesAPasswordOver72BytesThatTheVectorCutsAt72()
    {
        const string password = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored";
        const string hash = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui";
        Assert.True(BCrypt.Net.BCrypt.Verify(password, hash)); // which silently cuts it
        Assert.False(Bcrypt.Verify(password, hash));
        Assert.True(Bcrypt.Verify(password[..72], hash));
    }

    public static TheoryData<string, string> Utf8 => new()
    {
        { "Kk4DQuMMfZL9o", "$2b$04$cVWp4XaNU8a4v1uMRum2SO026BWLIoQMD/TXg5uZV.0P.uO8m3YEm" },
        { "9IeRXmnGxMYbs", "$2b$04$pQ7gRO7e6wx/936oXhNjrOUNOHL1D0h1N2IDbJZYs.1ppzSof6SPy" },
        { "xVQVbwa1S0M8r", "$2b$04$SQe9knOzepOVKoYXo9xTteNYr6MBwVz4tpriJVe3PNgYufGIsgKcW" },
        { "Zfgr26LWd22Za", "$2b$04$eH8zX.q5Q.j2hO1NkVYJQOM6KxntS/ow3.YzVmFrE4t//CoF4fvne" },
        { "Tg4daC27epFBE", "$2b$04$ahiTdwRXpUG2JLRcIznxc.s1.ydaPGD372bsGs8NqyYjLY1inG5n2" },
        { "xhQPMmwh5ALzW", "$2b$04$nQn78dV0hGHf5wUBe0zOFu8n07ZbWWOKoGasZKRspZxtt.vBRNMIy" },
        { "59je8h5Gj71tg", "$2b$04$cvXudZ5ugTg95W.rOjMITuM1jC0piCl3zF5cmGhzCibHZrNHkmckG" },
        { "wT4fHJa2N9WSW", "$2b$04$YYjtiq4Uh88yUsExO0RNTuEJ.tZlsONac16A8OcLHleWFjVawfGvO" },
        { "uSgFRnQdOgm4S", "$2b$04$WLTjgY/pZSyqX/fbMbJzf.qxCeTMQOzgL.CimRjMHtMxd/VGKojMu" },
        { "tEPtJZXur16Vg", "$2b$04$2moPs/x/wnCfeQ5pCheMcuSJQ/KYjOZG780UjA/SiR.KsYWNrC7SG" },
        { "vvho8C6nlVf9K", "$2b$04$HrEYC/AQ2HS77G78cQDZQ.r44WGcruKw03KHlnp71yVQEwpsi3xl2" },
        { "5auCCY9by0Ruf", "$2b$04$vVYgSTfB8KVbmhbZE/k3R.ux9A0lJUM4CZwCkHI9fifke2.rTF7MG" },
        { "GtTkR6qn2QOZW", "$2b$04$JfoNrR8.doieoI8..F.C1OQgwE3uTeuardy6lw0AjALUzOARoyf2m" },
        { "zKo8vdFSnjX0f", "$2b$04$HP3I0PUs7KBEzMBNFw7o3O7f/uxaZU7aaDot1quHMgB2yrwBXsgyy" },
        { "I9VfYlacJiwiK", "$2b$04$xnFVhJsTzsFBTeP3PpgbMeMREb6rdKV9faW54Sx.yg9plf4jY8qT6" },
        { "VFPO7YXnHQbQO", "$2b$04$WQp9.igoLqVr6Qk70mz6xuRxE0RttVXXdukpR9N54x17ecad34ZF6" },
        { "VDx5BdxfxstYk", "$2b$04$xgZtlonpAHSU/njOCdKztOPuPFzCNVpB4LGicO4/OGgHv.uKHkwsS" },
        { "dEe6XfVGrrfSH", "$2b$04$2Siw3Nv3Q/gTOIPetAyPr.GNj3aO0lb1E5E9UumYGKjP9BYqlNWJe" },
        { "cTT0EAFdwJiLn", "$2b$04$7/Qj7Kd8BcSahPO4khB8me4ssDJCW3r4OGYqPF87jxtrSyPj5cS5m" },
        { "J8eHUDuxBB520", "$2b$04$VvlCUKbTMjaxaYJ.k5juoecpG/7IzcH1AkmqKi.lIZMVIOLClWAk." },
        { "U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
        { "U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK" },
        { "U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a" },
    };

    /// <summary>Passwords that aren't UTF-8, as bytes.</summary>
    public static TheoryData<byte[], string> NotUtf8 => new()
    {
        { [0xa3], "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq" },
        { [0x7d, 0x3e, 0xb3, 0xfe, 0xf1, 0x8b, 0xa0, 0xe6, 0x28, 0xa2, 0x4c, 0x7a, 0x71, 0xc3, 0x50, 0x7f, 0xcc, 0xc8, 0x62, 0x7b, 0xf9, 0x14, 0xf6, 0xf6, 0x60, 0x81, 0x47, 0x35, 0xec, 0x1d, 0x87, 0x10, 0xbf, 0xa7, 0xe1, 0x7d, 0x49, 0x37, 0x20, 0x96, 0xdf, 0x63, 0xf2, 0xbf, 0xb3, 0x56, 0x68, 0xdf, 0x4d, 0x88, 0x71, 0xf7, 0xff, 0x1b, 0x82, 0x7e, 0x7a, 0x13, 0xdd, 0xe9, 0x84, 0x00, 0xdd, 0x34], "$2b$10$keO.ZZs22YtygVF6BLfhGOI/JjshJYPp8DZsUtym6mJV2Eha2Hdd." },
        { [0x67, 0x37, 0x0d, 0x01, 0xf3, 0xd4, 0xd0, 0xa9, 0x4a, 0x42, 0x5e, 0x18, 0x00, 0x37, 0x50, 0xb2, 0x4e, 0xc7, 0x1c, 0xee, 0x87, 0x26, 0x83, 0x43, 0x8b, 0xe8, 0x18, 0xc5, 0x3e, 0x86, 0x14, 0x2f, 0xd6, 0xcc, 0x1c, 0x4a, 0xde, 0xd7, 0x69, 0x78, 0xeb, 0xde, 0x4f, 0xef, 0xe1, 0x69, 0xac, 0xcb, 0x03, 0x96, 0x76, 0x31, 0x27, 0x20, 0xd6, 0x40, 0x2e, 0x6d, 0xa5, 0x21, 0xa0, 0xef, 0xc0, 0x28], "$2a$04$tecY.9ylRInW/rAAzXCXPOOlyYeCNzmNTzPDNSIFztFMKbvs/s5XG" },
    };
}
