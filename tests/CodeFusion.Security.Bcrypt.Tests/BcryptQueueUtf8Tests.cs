using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CodeFusion.Security.Tests;

/// <summary>The byte overloads of <see cref="BcryptQueue"/>: copied before they return, and the Try forms' statuses.</summary>
public class BcryptQueueUtf8Tests
{
    static readonly string Hash4 = Bcrypt.Hash("password123", 4);
    static readonly byte[] Hash4Ascii = Encoding.ASCII.GetBytes(Hash4);
    static readonly string SlowHash = Bcrypt.Hash("slow", 13);

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    static BcryptQueue Queue(int threads = 1, int lanes = 5, int? maxQueued = null, int windowMs = 0) =>
        new(new BcryptQueueOptions { Threads = threads, Lanes = lanes, MaxQueued = maxQueued, BatchWindow = TimeSpan.FromMilliseconds(windowMs) });

    static async Task<ValueTask<bool>> Occupy(BcryptQueue q)
    {
        var slow = q.VerifyAsync("slow", SlowHash, Ct);
        var sw = Stopwatch.StartNew();
        while (q.QueueLength != 0)
        {
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), "timed out");
            await Task.Delay(1, Ct);
        }
        return slow;
    }

    [Fact]
    public async Task VerifyAsyncAgreesWithTheStringOverload()
    {
        using var q = Queue(threads: 2);
        var random = new Random(7);
        string[] passwords = ["", "\0", "password123", new string('a', 72), new string('a', 73), new string('é', 36), new string('a', 69) + "😀", "pässwörd"];
        foreach (string password in passwords.Concat(Enumerable.Range(0, 20).Select(_ => RandomText(random))))
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(password);
            foreach (char revision in "aby")
            {
                var salt = new byte[16];
                random.NextBytes(salt);
                string hash = BCrypt.Net.BCrypt.HashPassword(password, Support.Settings(4, salt, revision));
                byte[] ascii = Encoding.ASCII.GetBytes(hash);
                bool expected = Bcrypt.Verify(password, hash);
                Assert.Equal(utf8.Length <= 72, expected);
                Assert.Equal(expected, await q.VerifyAsync(password, hash, Ct));
                Assert.Equal(expected, await q.VerifyAsync(utf8, ascii, Ct));
                Assert.Equal(expected ? BcryptStatus.Match : BcryptStatus.NoMatch, await q.TryVerifyAsync(utf8, ascii, Ct));
                Assert.False(await q.VerifyAsync([.. utf8, (byte)'x'], ascii, Ct));
            }
        }
    }

    /// <summary>Up to 24 characters from ASCII, Latin-1, CJK and astral planes: 1 to 4 bytes each, some past 72.</summary>
    static string RandomText(Random random)
    {
        var text = new StringBuilder();
        for (int i = random.Next(25); i > 0; i--)
            text.Append(random.Next(4) switch
            {
                0 => ((char)random.Next(0, 128)).ToString(),
                1 => ((char)random.Next(0xa0, 0x800)).ToString(),
                2 => ((char)random.Next(0x4e00, 0x9fff)).ToString(),
                _ => char.ConvertFromUtf32(random.Next(0x1f300, 0x1f64f)),
            });
        return text.ToString();
    }

    [Fact]
    public async Task HashAsyncMakesAHashEveryoneChecks()
    {
        using var q = Queue();
        BcryptHash hash = await q.HashAsync("pässwörd\0"u8, 5, Ct);
        Assert.Equal(60, hash.Length);
        string text = hash.ToString();
        Assert.StartsWith("$2b$05$", text, StringComparison.Ordinal);
        Assert.True(Bcrypt.Verify("pässwörd\0", text));
        Assert.True(BCrypt.Net.BCrypt.Verify("pässwörd\0", text));
        Assert.True(await q.VerifyAsync("pässwörd\0"u8, hash.AsSpan(), Ct));

        var tried = await q.TryHashAsync(""u8, 4, Ct);
        Assert.Equal(BcryptStatus.Hashed, tried.Status);
        Assert.True(Bcrypt.Verify("", tried.Hash.ToString()));
    }

    [Fact]
    public async Task AHashCopiesAndFormatsExactly()
    {
        using var q = Queue();
        BcryptHash hash = await q.HashAsync("x"u8, 4, Ct);
        string text = hash.ToString();

        var bytes = Enumerable.Repeat((byte)0xEE, 61).ToArray();
        hash.CopyTo(bytes);
        Assert.Equal(text, Encoding.ASCII.GetString(bytes, 0, 60));
        Assert.Equal(0xEE, bytes[60]);
        Assert.Throws<ArgumentException>(() => hash.CopyTo(new byte[59]));

        Assert.False(hash.TryFormat(new byte[59], out int written));
        Assert.Equal(0, written);
        Assert.True(hash.TryFormat(new byte[60], out written));
        Assert.Equal(60, written);

        var chars = new char[70];
        Assert.False(hash.TryFormat(chars.AsSpan(0, 59), out written));
        Assert.Equal(0, written);
        Assert.True(hash.TryFormat(chars, out written));
        Assert.Equal(text, new string(chars, 0, written));
        Assert.Equal(text, $"{hash}");

        Assert.Equal(0, default(BcryptHash).Length);
        Assert.Equal("", default(BcryptHash).ToString());
        Assert.True(default(BcryptHash).TryFormat(Span<byte>.Empty, out written));
        Assert.Equal(0, written);
    }

    /// <summary>The caller's buffers belong to it again as soon as the call returns, while the hash still waits.</summary>
    [Fact]
    public async Task BuffersCanBeReusedAsSoonAsTheCallReturns()
    {
        using var q = Queue();
        var slow = await Occupy(q);
        byte[] password = "password123"u8.ToArray(), hash = (byte[])Hash4Ascii.Clone(), newPassword = "new one"u8.ToArray();
        var check = q.VerifyAsync(password, hash, Ct);
        var tried = q.TryVerifyAsync(password, hash, Ct);
        var made = q.HashAsync(newPassword, 4, Ct);
        password.AsSpan().Fill((byte)'z');
        hash.AsSpan(29).Fill((byte)'.');
        newPassword.AsSpan().Clear();
        Assert.Equal(3, q.QueueLength);

        Assert.True(await slow);
        Assert.True(await check);
        Assert.Equal(BcryptStatus.Match, await tried);
        Assert.True(Bcrypt.Verify("new one", (await made).ToString()));
    }

    [Fact]
    public async Task MalformedHashesAndLongPasswordsAreAnsweredWithoutQueueing()
    {
        using var q = Queue();
        var malformed = q.VerifyAsync("password123"u8, "$2b$04$nope"u8, Ct);
        var tooLong = q.VerifyAsync(new byte[73], Hash4Ascii, Ct);
        var triedMalformed = q.TryVerifyAsync("password123"u8, Hash4Ascii.AsSpan(0, 59), Ct);
        Assert.True(malformed.IsCompletedSuccessfully && tooLong.IsCompletedSuccessfully && triedMalformed.IsCompletedSuccessfully);
        Assert.False(await malformed);
        Assert.False(await tooLong);
        Assert.Equal(BcryptStatus.NoMatch, await triedMalformed);
        Assert.Equal(0, q.HashesRun);

        Assert.Equal("passwordUtf8", Assert.Throws<ArgumentException>(() => q.HashAsync(new byte[73], 4, Ct)).ParamName);
        Assert.Throws<ArgumentException>(() => q.TryHashAsync(new byte[73], 4, Ct));
        Assert.Throws<ArgumentOutOfRangeException>(() => q.HashAsync("x"u8, 3, Ct));
        Assert.Throws<ArgumentOutOfRangeException>(() => q.TryHashAsync("x"u8, 32, Ct));
        Assert.True(await q.VerifyAsync("password123"u8, Hash4Ascii, Ct)); // the refusals left nothing behind
        Assert.Equal(1, q.HashesRun);
    }

    [Fact]
    public async Task AFullQueueIsBusyWithoutAnException()
    {
        using var q = Queue(maxQueued: 1);
        var slow = await Occupy(q);
        var queued = q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct);
        // Refused on this thread, so only this thread's exceptions count: other tests run meanwhile.
        int exceptions = 0, thread = Environment.CurrentManagedThreadId;
        EventHandler<System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs> count = (_, _) =>
        {
            if (Environment.CurrentManagedThreadId == thread) Interlocked.Increment(ref exceptions);
        };
        AppDomain.CurrentDomain.FirstChanceException += count;
        ValueTask<BcryptStatus> busy;
        ValueTask<BcryptHashResult> busyHash;
        try
        {
            busy = q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct);
            busyHash = q.TryHashAsync("x"u8, 4, Ct);
        }
        finally { AppDomain.CurrentDomain.FirstChanceException -= count; }
        Assert.Equal(0, exceptions);
        Assert.True(busy.IsCompletedSuccessfully && busyHash.IsCompletedSuccessfully);
        Assert.Equal(BcryptStatus.Busy, await busy);
        Assert.Equal(BcryptStatus.Busy, (await busyHash).Status);
        Assert.Equal(0, (await busyHash).Hash.Length);

        // The throwing forms still throw.
        await Assert.ThrowsAsync<BcryptQueueFullException>(async () => await q.VerifyAsync("password123"u8, Hash4Ascii, Ct));
        await Assert.ThrowsAsync<BcryptQueueFullException>(async () => await q.HashAsync("x"u8, 4, Ct));
        Assert.Equal(4, q.Refused);

        Assert.True(await slow);
        Assert.Equal(BcryptStatus.Match, await queued);
        Assert.Equal(BcryptStatus.Match, await q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct)); // room again
        Assert.Equal(3, q.HashesRun);
    }

    [Fact]
    public async Task CancellingBeforeAWorkerTakesItIsCancelledWithoutAnException()
    {
        using var q = Queue();
        var slow = await Occupy(q);
        using var cts = new CancellationTokenSource();
        var check = q.TryVerifyAsync("password123"u8, Hash4Ascii, cts.Token);
        var hash = q.TryHashAsync("x"u8, 4, cts.Token);
        var throwing = q.VerifyAsync("password123"u8, Hash4Ascii, cts.Token);
        var throwingHash = q.HashAsync("x"u8, 4, cts.Token);
        Assert.Equal(4, q.QueueLength);

        await cts.CancelAsync();
        var sw = Stopwatch.StartNew();
        while (!(check.IsCompleted && hash.IsCompleted && throwing.IsCompleted && throwingHash.IsCompleted))
        {
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), "timed out");
            await Task.Delay(1, Ct);
        }
        // Succeeded, not cancelled: the Try forms carry no exception.
        Assert.True(check.IsCompletedSuccessfully && hash.IsCompletedSuccessfully);
        Assert.True(throwing.IsCanceled && throwingHash.IsCanceled);
        Assert.Equal(BcryptStatus.Cancelled, await check);
        var result = await hash;
        Assert.Equal(BcryptStatus.Cancelled, result.Status);
        Assert.Equal(0, result.Hash.Length);

        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await throwing);
        Assert.Equal(cts.Token, ex.CancellationToken);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await throwingHash);
        Assert.False(slow.IsCompleted); // ended while the worker was still busy
        Assert.Equal(4, q.Cancelled);
        Assert.Equal(0, q.QueueLength);

        Assert.True(await slow);
        Assert.Equal(BcryptStatus.Match, await q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct));
        Assert.Equal(2, q.HashesRun); // the cancelled ones never ran
    }

    [Fact]
    public async Task AnAlreadyCancelledTokenIsAnsweredAtOnce()
    {
        using var q = Queue();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var check = q.TryVerifyAsync("password123"u8, Hash4Ascii, cts.Token);
        var hash = q.TryHashAsync("x"u8, 4, cts.Token);
        Assert.True(check.IsCompletedSuccessfully && hash.IsCompletedSuccessfully);
        Assert.Equal(BcryptStatus.Cancelled, await check);
        Assert.Equal(BcryptStatus.Cancelled, (await hash).Status);
        Assert.True(q.VerifyAsync("password123"u8, Hash4Ascii, cts.Token).IsCanceled);
        Assert.True(q.HashAsync("x"u8, 4, cts.Token).IsCanceled);
        Assert.Equal(0, q.HashesRun);
        Assert.Equal(0, q.QueueLength);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ATokenFiringWhileTheCallIsQueuedIsCancelled(bool hash)
    {
        using var q = Queue();
        using var cts = new CancellationTokenSource();
        q.BeforeLinkForTests = cts.Cancel;
        BcryptStatus status = hash ? (await q.TryHashAsync("x"u8, 4, cts.Token)).Status : await q.TryVerifyAsync("password123"u8, Hash4Ascii, cts.Token);
        q.BeforeLinkForTests = null;
        Assert.Equal(BcryptStatus.Cancelled, status);
        Assert.Equal(1, q.Cancelled);
        Assert.Equal(0, q.Entries);
        Assert.Equal(BcryptStatus.Match, await q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct));
        Assert.Equal(1, q.HashesRun);
    }

    [Fact]
    public async Task DisposeStillThrowsForTheTryForms()
    {
        var q = Queue();
        var slow = await Occupy(q);
        var waiting = q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct);
        q.Dispose();
        Assert.True(await slow);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await waiting);
        Assert.Throws<ObjectDisposedException>(() => q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct));
        Assert.Throws<ObjectDisposedException>(() => q.TryHashAsync("x"u8, 4, Ct));
        Assert.Throws<ObjectDisposedException>(() => q.VerifyAsync("password123"u8, Hash4Ascii, Ct));
        Assert.Throws<ObjectDisposedException>(() => q.HashAsync("x"u8, 4, Ct));
    }

    /// <summary>Requests go back to one pool whichever overload used them: no state leaks from one kind to the next.</summary>
    [Fact]
    public async Task EveryKindOfCallSharesThePoolSoundly()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 2, Lanes = 3 });
        var tasks = Enumerable.Range(0, 160).Select(i => Task.Run(async () =>
        {
            byte[] mine = Encoding.UTF8.GetBytes($"pw{i}");
            switch (i % 8)
            {
                case 0: Assert.True(await q.VerifyAsync("password123", Hash4, Ct)); break;
                case 1: Assert.False(await q.VerifyAsync("password124"u8.ToArray(), Hash4Ascii, Ct)); break;
                case 2: Assert.Equal(BcryptStatus.Match, await q.TryVerifyAsync("password123"u8.ToArray(), Hash4Ascii, Ct)); break;
                case 3: Assert.Equal(BcryptStatus.NoMatch, await q.TryVerifyAsync("password12"u8.ToArray(), Hash4Ascii, Ct)); break;
                case 4: Assert.True(Bcrypt.Verify($"pw{i}", await q.HashAsync($"pw{i}", 4, Ct))); break;
                case 5: Assert.True(Bcrypt.Verify($"pw{i}", (await q.HashAsync(mine, 4, Ct)).ToString())); break;
                case 6:
                    var r = await q.TryHashAsync(mine, 4, Ct);
                    Assert.Equal(BcryptStatus.Hashed, r.Status);
                    Assert.True(Bcrypt.Verify($"pw{i}", r.Hash.ToString()));
                    break;
                default: Assert.False(await q.VerifyAsync("password123", Bcrypt.Hash("other", 4), Ct)); break;
            }
        }, Ct)).ToArray();
        await Task.WhenAll(tasks);
        Assert.Equal(160, q.HashesRun);
        Assert.Equal(0, q.QueueLength);
    }

    // ---------- the contest server's scenarios (csharp-kestrel-xeonfx PasswordsBytesTests), on this queue ----------

    static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public async Task EachCallerGetsItsOwnAnswerFromABatch()
    {
        using var q = Queue(windowMs: 0);
        bool[] good = [true, false, true, true, false, false, true, false, true];
        var checks = good.Select(g => q.TryVerifyAsync(B(g ? "password123" : "password124"), Hash4Ascii, Ct)).ToArray();
        string[] passwords = ["alpha", "beta", "gamma", "é😀"];
        var hashes = passwords.Select(p => q.TryHashAsync(B(p), 4, Ct)).ToArray();

        for (int i = 0; i < good.Length; i++) Assert.Equal(good[i] ? BcryptStatus.Match : BcryptStatus.NoMatch, await checks[i]);
        for (int i = 0; i < passwords.Length; i++)
        {
            var made = await hashes[i];
            Assert.Equal(BcryptStatus.Hashed, made.Status);
            byte[] text = new byte[Bcrypt.HashLength];
            made.CopyTo(text);
            string hash = Encoding.ASCII.GetString(text);
            Assert.StartsWith("$2b$04$", hash, StringComparison.Ordinal);
            Assert.True(BCrypt.Net.BCrypt.Verify(passwords[i], hash));
            Assert.False(BCrypt.Net.BCrypt.Verify(passwords[i] + "x", hash));
            Assert.Equal(BcryptStatus.Match, await q.TryVerifyAsync(B(passwords[i]), text, Ct));
        }
    }

    [Theory]
    [InlineData("not a hash")]
    [InlineData("")]
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899w")] // 59 characters
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wqq")] // 61
    [InlineData("$2x$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")]
    [InlineData("$2a$03$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // cost below 4
    [InlineData("$2a$32$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")]
    [InlineData("$2a$1a$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")]
    [InlineData("$2a$10$ZSfEoPvlcsj2XfvsSeK2!em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq")] // not in the alphabet
    public async Task AMalformedHashIsNoMatchAtOnceWithoutQueueing(string hash)
    {
        using var q = Queue();
        var check = q.TryVerifyAsync("password123"u8, B(hash), Ct);
        Assert.True(check.IsCompletedSuccessfully);
        Assert.Equal(BcryptStatus.NoMatch, await check);
        Assert.Equal(0, q.HashesRun);
    }

    /// <summary>Past the queue's limit a call is Busy at once: no exception, nothing queued, and the calls that got in
    /// still get their answers.</summary>
    [Fact]
    public async Task AFloodPastTheLimitIsBusyAtOnce()
    {
        const int limit = 40, extra = 10;
        using var q = Queue(maxQueued: limit);
        var slow = await Occupy(q);
        var all = Enumerable.Range(0, limit + extra).Select(i => q.TryVerifyAsync(i % 2 == 0 ? "password123"u8 : "password124"u8, Hash4Ascii, Ct)).ToArray();
        int busy = 0;
        for (int i = 0; i < all.Length; i++) // each awaited exactly once
        {
            bool atOnce = all[i].IsCompleted;
            var r = await all[i];
            if (r == BcryptStatus.Busy)
            {
                Assert.True(atOnce);
                Assert.True(i >= limit, $"call {i} was refused with room left");
                busy++;
            }
            else Assert.Equal(i % 2 == 0 ? BcryptStatus.Match : BcryptStatus.NoMatch, r);
        }
        Assert.Equal(extra, busy);
        Assert.Equal(extra, q.Refused);
        Assert.True(await slow);
        Assert.Equal(0, q.QueueLength);
    }

    /// <summary>Reading a read result again (ValueTask.Result goes straight to GetResult) throws and must not pool the
    /// request a second time: two later calls would then share it and could swap answers.</summary>
    [Fact]
    public async Task AStaleReadDoesNotPoolTheRequestTwice()
    {
        using var q = Queue();
        var check = q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct);
        Assert.Equal(BcryptStatus.Match, await check);
        Assert.Throws<InvalidOperationException>(() => check.Result);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await check);
        for (int round = 0; round < 20; round++)
        {
            // two calls sharing a request would leave one waiting for good: fail after a while instead of hanging
            var good = q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), Ct);
            var bad = q.TryVerifyAsync("password124"u8, Hash4Ascii, Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), Ct);
            Assert.Equal(BcryptStatus.Match, await good);
            Assert.Equal(BcryptStatus.NoMatch, await bad);
        }
    }

    /// <summary>The stored hash is compared in full, its last character too (as Go's bcrypt does), and its salt counts.</summary>
    [Fact]
    public async Task AStoredHashDifferingInOneCharacterDoesNotMatch()
    {
        using var q = Queue();
        byte[] hash = (byte[])Hash4Ascii.Clone();
        Assert.Equal(BcryptStatus.Match, await q.TryVerifyAsync("password123"u8, hash, Ct));
        foreach (byte c in "./AZaz09"u8.ToArray())
        {
            if (c == Hash4Ascii[^1]) continue;
            hash[^1] = c;
            Assert.Equal(BcryptStatus.NoMatch, await q.TryVerifyAsync("password123"u8, hash, Ct));
        }
        hash[^1] = Hash4Ascii[^1];
        hash[20] = hash[20] == (byte)'a' ? (byte)'b' : (byte)'a'; // a salt character
        Assert.Equal(BcryptStatus.NoMatch, await q.TryVerifyAsync("password123"u8, hash, Ct));
    }

    /// <summary>A result with no hash has nothing to copy.</summary>
    [Fact]
    public async Task ABusyOrCancelledHashHasNothingToCopy()
    {
        using var q = Queue();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var none = await q.TryHashAsync("alpha"u8, 4, cts.Token);
        Assert.Equal(BcryptStatus.Cancelled, none.Status);
        Assert.Throws<InvalidOperationException>(() => none.CopyTo(new byte[60]));
        var made = await q.TryHashAsync("alpha"u8, 4, Ct);
        Assert.Throws<ArgumentException>(() => made.CopyTo(new byte[59]));
        var text = new byte[60];
        made.CopyTo(text);
        Assert.True(Bcrypt.Verify("alpha"u8, text));
    }

    /// <summary>
    /// The batching window runs from the first call's arrival, not from when a worker takes it: a call that waited out
    /// the window behind a long run runs at once instead of waiting a second window for company.
    /// </summary>
    [Fact]
    public async Task ACallOlderThanTheWindowRunsWithoutWaitingAgain()
    {
        var window = TimeSpan.FromMilliseconds(300);
        using var q = Queue(windowMs: (int)window.TotalMilliseconds);
        var start = Stopwatch.StartNew();
        var slow = Enumerable.Range(0, Bcrypt.MaxLanes).Select(_ => q.HashAsync("pw"u8, 13, Ct)).ToArray(); // well over the window
        var late = q.TryVerifyAsync("password123"u8, Hash4Ascii, Ct);
        foreach (var s in slow) Assert.Equal(60, (await s).Length);
        var run = start.Elapsed;
        Assert.True(run > window + TimeSpan.FromMilliseconds(200), $"the run took only {run}, so the late call wasn't older than the window");
        Assert.Equal(BcryptStatus.Match, await late);
        var after = start.Elapsed - run;
        Assert.True(after < window / 2, $"waited {after} after the run");
        Assert.Equal(2, q.Batches);
    }
}
