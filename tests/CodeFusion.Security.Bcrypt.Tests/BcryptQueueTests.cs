using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CodeFusion.Security.Tests;

public class BcryptQueueTests
{
    static readonly string Hash4 = Bcrypt.Hash("password123", 4);

    /// <summary>A check that keeps a worker busy for a few hundred milliseconds.</summary>
    static readonly string SlowHash = Bcrypt.Hash("slow", 13);

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    static BcryptQueue Queue(int threads = 1, int lanes = 5, int windowMs = 0, int? maxQueued = null) =>
        new(new BcryptQueueOptions { Threads = threads, Lanes = lanes, BatchWindow = TimeSpan.FromMilliseconds(windowMs), MaxQueued = maxQueued });

    /// <summary>Starts a slow check and returns once a worker has taken it, so what follows queues behind it.</summary>
    static async Task<ValueTask<bool>> Occupy(BcryptQueue q)
    {
        var slow = q.VerifyAsync("slow", SlowHash, Ct);
        await Until(() => q.QueueLength == 0);
        return slow;
    }

    static async Task Until(Func<bool> condition)
    {
        var sw = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), "timed out");
            await Task.Delay(1, Ct);
        }
    }

    [Fact]
    public async Task HashesArrivingWithinTheWindowShareOneRun()
    {
        using var q = Queue(windowMs: 500);
        var first = q.VerifyAsync("password123", Hash4, Ct);
        await Task.Delay(50, Ct);
        var later = q.VerifyAsync("password124", Hash4, Ct);
        var last = q.HashAsync("new", 4, Ct);

        Assert.True(await first);
        Assert.False(await later);
        Assert.True(Bcrypt.Verify("new", await last));
        Assert.Equal(1, q.Batches);
        Assert.Equal(3, q.HashesRun);
    }

    [Fact]
    public async Task AFullRunStartsWithoutWaitingOutTheWindow()
    {
        using var q = Queue(windowMs: 30_000);
        var sw = Stopwatch.StartNew();
        var all = Enumerable.Range(0, Bcrypt.MaxLanes).Select(_ => q.VerifyAsync("password123", Hash4, Ct)).ToArray();
        foreach (var t in all) Assert.True(await t);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
        Assert.Equal(1, q.Batches);
    }

    [Theory]
    [InlineData(5, 7, 2)] // 5 lanes: the backlog of 7 runs as 5 + 2
    [InlineData(2, 4, 2)]
    [InlineData(1, 3, 3)]
    public async Task ABacklogRunsInRunsOfTheLaneCount(int lanes, int backlog, int runs)
    {
        using var q = Queue(lanes: lanes);
        var slow = await Occupy(q);
        var all = Enumerable.Range(0, backlog).Select(i => q.VerifyAsync(i % 2 == 0 ? "password123" : "wrong", Hash4, Ct)).ToArray();
        Assert.True(await slow);
        for (int i = 0; i < backlog; i++) Assert.Equal(i % 2 == 0, await all[i]);
        Assert.Equal(1 + runs, q.Batches);
    }

    [Fact]
    public async Task CallsPastTheQueueLimitAreRefusedAtOnce()
    {
        using var q = Queue(maxQueued: 3);
        var slow = await Occupy(q);
        var queued = Enumerable.Range(0, 3).Select(_ => q.VerifyAsync("password123", Hash4, Ct)).ToArray();
        var refused = q.VerifyAsync("password123", Hash4, Ct);
        var refusedHash = q.HashAsync("x", 4, Ct);
        Assert.True(refused.IsFaulted);
        await Assert.ThrowsAsync<BcryptQueueFullException>(async () => await refused);
        await Assert.ThrowsAsync<BcryptQueueFullException>(async () => await refusedHash);
        Assert.Equal(2, q.Refused);
        Assert.True(await slow);
        foreach (var t in queued) Assert.True(await t);
        Assert.Equal(0, q.QueueLength);
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct)); // room again
    }

    [Fact]
    public async Task ACancelledFirstHashDoesNotStartTheWindowOrARun()
    {
        using var q = Queue(windowMs: 300);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var cancelled = q.VerifyAsync("password123", Hash4, cts.Token);
        Assert.True(cancelled.IsCanceled);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await cancelled);
        var sw = Stopwatch.StartNew();
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct));
        Assert.Equal(1, q.Batches);
        // the live hash waited its own window, measured from its own arrival
        Assert.True(sw.Elapsed >= TimeSpan.FromMilliseconds(250), $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task CancellingAQueuedHashEndsItAtOnceAndItNeverRuns()
    {
        using var q = Queue();
        var slow = await Occupy(q);
        using var cts = new CancellationTokenSource();
        var check = q.VerifyAsync("password123", Hash4, cts.Token);
        var hash = q.HashAsync("x", 4, cts.Token);
        Assert.Equal(2, q.QueueLength);
        await cts.CancelAsync();

        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await check);
        Assert.Equal(cts.Token, ex.CancellationToken);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await hash);
        Assert.False(slow.IsCompleted); // ended while the worker was still busy
        Assert.Equal(0, q.QueueLength);
        Assert.Equal(2, q.Cancelled);

        Assert.True(await slow);
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct));
        Assert.Equal(2, q.HashesRun); // the slow one and the last; the cancelled ones never ran
    }

    [Fact]
    public async Task CancellingAfterAWorkerTookAHashStillGivesItsResult()
    {
        using var q = Queue();
        using var cts = new CancellationTokenSource();
        var slow = q.VerifyAsync("slow", SlowHash, cts.Token);
        await Until(() => q.QueueLength == 0);
        await cts.CancelAsync();
        Assert.True(await slow);
        Assert.Equal(0, q.Cancelled);
    }

    [Fact]
    public async Task EveryRequestCompletesCorrectly()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 2, Lanes = 3 });
        string other = Bcrypt.Hash("other", 5);
        var tasks = Enumerable.Range(0, 120).Select(i => Task.Run(async () =>
        {
            switch (i % 4)
            {
                case 0: Assert.True(await q.VerifyAsync("password123", Hash4, Ct)); break;
                case 1: Assert.False(await q.VerifyAsync("password124", Hash4, Ct)); break;
                case 2: Assert.True(await q.VerifyAsync("other", other, Ct)); break;
                default:
                    string h = await q.HashAsync($"pw{i}", 4, Ct);
                    Assert.True(Bcrypt.Verify($"pw{i}", h));
                    break;
            }
        }, Ct)).ToArray();
        await Task.WhenAll(tasks);
        Assert.Equal(120, q.HashesRun);
        Assert.Equal(0, q.QueueLength);
        Assert.InRange(q.Batches, 40, 120);
    }

    [Fact]
    public async Task MalformedHashesAndUnusablePasswordsAreFalseWithoutQueueing()
    {
        using var q = Queue();
        var malformed = q.VerifyAsync("password123", "$2b$04$nope", Ct);
        var tooLong = q.VerifyAsync(new string('a', 73), Hash4, Ct);
        Assert.True(malformed.IsCompletedSuccessfully);
        Assert.True(tooLong.IsCompletedSuccessfully);
        Assert.False(await malformed);
        Assert.False(await tooLong);
        Assert.Equal(0, q.Batches);
    }

    [Fact]
    public async Task StrayChecksumBitsAreRefusedWithoutHashing()
    {
        using var q = Queue();
        var check = q.VerifyAsync("password123", StrayChecksumBits(Hash4), Ct);
        Assert.True(check.IsCompletedSuccessfully);
        Assert.False(await check);
        Assert.Equal(0, q.HashesRun);
    }

    /// <summary>The hash with its last character's two unused bits set: it can never match.</summary>
    internal static string StrayChecksumBits(string hash)
    {
        const string alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int last = alphabet.IndexOf(hash[^1], StringComparison.Ordinal);
        Assert.Equal(0, last & 3); // as bcrypt writes it
        return hash[..^1] + alphabet[last + 1];
    }

    [Fact]
    public async Task HashAsyncRefusesBadArgumentsAtOnce()
    {
        using var q = Queue();
        Assert.Throws<ArgumentException>(() => q.HashAsync(new string('a', 73), 4, Ct));
        Assert.Throws<ArgumentOutOfRangeException>(() => q.HashAsync("x", 3, Ct));
        Assert.Throws<ArgumentNullException>(() => q.HashAsync((string)null!, 4, Ct));
        Assert.Throws<ArgumentNullException>(() => q.VerifyAsync(null!, Hash4, Ct));
        Assert.Throws<ArgumentNullException>(() => q.VerifyAsync("x", null!, Ct));
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct)); // the refusals left nothing behind
    }

    [Fact]
    public async Task EnhancedHashesGoThroughTheQueue()
    {
        using var q = Queue();
        string longPassword = new('é', 200);
        string hash = await q.HashAsync(longPassword, 4, BcryptPrehash.Sha384, Ct);
        Assert.True(Bcrypt.EnhancedVerify(longPassword, hash));
        Assert.True(await q.VerifyAsync(longPassword, hash, BcryptPrehash.Sha384, Ct));
        Assert.False(await q.VerifyAsync(longPassword, hash, Ct));
        Assert.True(await q.VerifyAsync("x", BCrypt.Net.BCrypt.EnhancedHashPassword("x", 4, BCrypt.Net.HashType.SHA256), BcryptPrehash.Sha256, Ct));
    }

    [Fact]
    public async Task ResultsArriveOnThePoolNotOnAWorker()
    {
        using var q = Queue();
        // On the pool, where no synchronization context moves the continuation elsewhere.
        var thread = await Task.Run(async () =>
        {
            await q.VerifyAsync("password123", Hash4, Ct);
            return Thread.CurrentThread;
        }, Ct);
        Assert.True(thread.IsThreadPoolThread);
        Assert.DoesNotContain("bcrypt", thread.Name ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task AwaitingTwiceThrows()
    {
        using var q = Queue();
        var check = q.VerifyAsync("password123", Hash4, Ct);
        Assert.True(await check);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await check);

        // After its request was reused, the stale ValueTask still throws and the new one is unharmed.
        var next = q.VerifyAsync("password124", Hash4, Ct);
        Assert.Same(Source(check), Source(next));
        Assert.Throws<InvalidOperationException>(() => check.IsCompleted);
        Assert.False(await next);
    }

    /// <summary>
    /// A cancelled request stays in the queue until a worker passes it, so its result is read before the request can
    /// be reused. A second read then must not release it again: it would be reused while still queued.
    /// </summary>
    [Fact]
    public async Task AwaitingACancelledResultTwiceThrowsAndLeavesTheQueueSound()
    {
        using var q = Queue();
        var slow = await Occupy(q);
        using var cts = new CancellationTokenSource();
        var check = q.VerifyAsync("password123", Hash4, cts.Token);
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await check);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await check);

        Assert.True(await slow); // the worker now passes the cancelled entry
        var after = Enumerable.Range(0, 4).Select(i => q.VerifyAsync(i % 2 == 0 ? "password123" : "wrong", Hash4, Ct)).ToArray();
        for (int i = 0; i < after.Length; i++) Assert.Equal(i % 2 == 0, await after[i]);
        Assert.Equal(5, q.HashesRun);
    }

    /// <summary>
    /// .Result or .GetAwaiter().GetResult() on a pending ValueTask doesn't block: it reads the result early. That
    /// must not free the request a worker still holds, or another caller would get this one's hash.
    /// </summary>
    [Fact]
    public async Task ReadingAResultBeforeItIsReadyThrowsAndHarmsNothing()
    {
        using var q = Queue();
        var slow = await Occupy(q);
        var check = q.VerifyAsync("password123", Hash4, Ct);
        var hash = q.HashAsync("mine", 4, Ct);
        Assert.Throws<InvalidOperationException>(() => check.GetAwaiter().GetResult());
        Assert.Throws<InvalidOperationException>(() => hash.GetAwaiter().GetResult());

        // Others queue meanwhile, reusing whatever the pool holds.
        var others = Enumerable.Range(0, 3).Select(i => q.HashAsync($"other{i}", 4, Ct)).ToArray();
        Assert.True(await slow);
        Assert.True(await check);
        Assert.True(Bcrypt.Verify("mine", await hash));
        for (int i = 0; i < others.Length; i++) Assert.True(Bcrypt.Verify($"other{i}", await others[i]));
    }

    /// <summary>A cheap check that shares a run with a costly hash completes when its own lane is done.</summary>
    [Fact]
    public async Task ACheapCheckDoesNotWaitForACostlierHashInItsRun()
    {
        using var q = Queue(windowMs: 300);
        var slow = q.VerifyAsync("slow", SlowHash, Ct);
        var cheap = q.VerifyAsync("password123", Hash4, Ct);
        Assert.True(await cheap);
        Assert.False(slow.IsCompleted);
        Assert.Equal(1, q.Batches);
        Assert.True(await slow);
    }

    [Fact]
    public async Task AnUnknownPrehashIsRefusedAtOnce()
    {
        using var q = Queue();
        Assert.Throws<ArgumentOutOfRangeException>(() => q.VerifyAsync("x", Hash4, (BcryptPrehash)9, Ct));
        Assert.Throws<ArgumentOutOfRangeException>(() => q.HashAsync("x", 4, (BcryptPrehash)(-1), Ct));
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct));
    }

    /// <summary>
    /// Cancelled requests leave the queue at once. Otherwise, with the workers busy, callers that give up (aborted HTTP
    /// requests under overload) would pile up entries past MaxQueued until a worker got round to them.
    /// </summary>
    [Fact]
    public async Task CancelledRequestsLeaveTheQueueAtOnce()
    {
        using var q = Queue(lanes: 1, maxQueued: 1);
        var slow = await Occupy(q);
        for (int i = 0; i < 200; i++)
        {
            using var cts = new CancellationTokenSource();
            var check = q.VerifyAsync("password123", Hash4, cts.Token);
            await cts.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await check);
        }
        Assert.False(slow.IsCompleted); // the worker was busy throughout
        Assert.Equal(0, q.Entries);
        Assert.Equal(0, q.QueueLength);
        Assert.Equal(0, q.Refused);
        Assert.Equal(200, q.Cancelled);
        Assert.True(await slow);
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct));
        Assert.Equal(2, q.HashesRun);
    }

    /// <summary>
    /// A token that fires while the call is still being queued (after its registration, before the request is linked)
    /// cancels it all the same: it never runs. Before this was handled, the cancellation found the request in no
    /// queue, took it for one a worker had, and the hash ran.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ATokenFiringWhileTheCallIsQueuedStillCancelsIt(bool hash)
    {
        using var q = Queue();
        using var cts = new CancellationTokenSource();
        q.BeforeLinkForTests = cts.Cancel;
        Task call = hash ? q.HashAsync("x", 4, cts.Token).AsTask() : q.VerifyAsync("password123", Hash4, cts.Token).AsTask();
        q.BeforeLinkForTests = null;
        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
        Assert.Equal(cts.Token, ex.CancellationToken);
        Assert.Equal(1, q.Cancelled);
        Assert.Equal(0, q.QueueLength);
        Assert.Equal(0, q.Entries);
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct)); // the queue and its wake-ups are intact
        Assert.Equal(1, q.HashesRun);
    }

    /// <summary>Dispose doesn't wait out the window of a run that a worker is still collecting.</summary>
    [Fact]
    public async Task DisposeCutsAWaitingRunShort()
    {
        var q = Queue(windowMs: 30_000);
        var check = q.VerifyAsync("password123", Hash4, Ct);
        await Until(() => q.QueueLength == 0); // taken; the worker now waits for more to join
        var sw = Stopwatch.StartNew();
        q.Dispose();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"Dispose took {sw.Elapsed}");
        Assert.True(await check); // what the worker had taken still runs
    }

    [Fact]
    public async Task RequestsAreReusedRoundAfterRound()
    {
        using var q = Queue();
        var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);
        for (int round = 0; round < 5; round++)
        {
            var checks = Enumerable.Range(0, 3).Select(_ => q.VerifyAsync("password123", Hash4, Ct)).ToArray();
            var hash = q.HashAsync("x", 4, Ct);
            foreach (var t in checks) seen.Add(Source(t));
            seen.Add(Source(hash));
            foreach (var t in checks) Assert.True(await t);
            Assert.True(Bcrypt.Verify("x", await hash));
        }
        Assert.Equal(4, seen.Count); // the first round's four, every round
    }

    [Fact]
    public async Task DisposeFailsWhatWaitsFinishesWhatRunsAndRefusesMore()
    {
        var q = Queue();
        var slow = await Occupy(q);
        var waiting = q.VerifyAsync("password123", Hash4, Ct);
        q.Dispose();
        Assert.True(await slow); // the worker finished the run it held
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await waiting);
        Assert.Throws<ObjectDisposedException>(() => q.VerifyAsync("password123", Hash4, Ct));
        Assert.Throws<ObjectDisposedException>(() => q.HashAsync("x", 4, Ct));
        q.Dispose(); // twice is fine
    }

    [Fact]
    public void BadOptionsAreRefused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BcryptQueue(new BcryptQueueOptions { Threads = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BcryptQueue(new BcryptQueueOptions { Lanes = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BcryptQueue(new BcryptQueueOptions { Lanes = 6 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BcryptQueue(new BcryptQueueOptions { BatchWindow = TimeSpan.FromMilliseconds(-1) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BcryptQueue(new BcryptQueueOptions { MaxQueued = 0 }));
        Assert.Throws<ArgumentNullException>(() => new BcryptQueue(new BcryptQueueOptions { ThreadName = null! }));
    }

    [Fact]
    public async Task DefaultOptionsWork()
    {
        using var q = new BcryptQueue();
        Assert.True(await q.VerifyAsync("password123", Hash4, Ct));
    }

    static object Source<T>(ValueTask<T> task) =>
        typeof(ValueTask<T>).GetField("_obj", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(task)!;
}
