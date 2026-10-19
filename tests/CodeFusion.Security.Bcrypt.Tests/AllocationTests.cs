using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace CodeFusion.Security.Tests;

/// <summary>Tests that measure the whole process: nothing else may run while they do.</summary>
[CollectionDefinition(nameof(Measuring), DisableParallelization = true)]
public sealed class Measuring;

// The queue is measured with no token, as most callers use it, and separately with a cancellable one.
#pragma warning disable xUnit1051

/// <summary>Exact bytes allocated, after a warm-up so the JIT, tiering and the queue's pool are settled.</summary>
[Collection(nameof(Measuring))]
public class AllocationTests
{
    static readonly string Hash4 = Bcrypt.Hash("password123", 4);
    const int Calls = 20;

    static long OnThisThread(Action action)
    {
        for (int i = 0; i < 3; i++) action();
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < Calls; i++) action();
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    // The queue tests measure every thread's bytes, inline in the test method: a helper taking an async lambda
    // would allocate that lambda's state machine on each call. They keep the least of three tries after a warm-up:
    // the test host's own threads may allocate meanwhile, which only ever adds, while a real per-call allocation
    // shows in every try.
    const int Tries = 4;

    [Fact]
    public void VerifyAllocatesNothing()
    {
        Assert.Equal(0, OnThisThread(() => Bcrypt.Verify("password123", Hash4)));
        Assert.Equal(0, OnThisThread(() => Bcrypt.Verify("wrong", Hash4)));
        Assert.Equal(0, OnThisThread(() => Bcrypt.Verify("password123", "malformed")));
        string tooLong = new('a', 100);
        Assert.Equal(0, OnThisThread(() => Bcrypt.Verify(tooLong, Hash4)));
    }

    [Fact]
    public void BatchVerifyAllocatesNothing()
    {
        string[] passwords = Enumerable.Repeat("password123", 11).ToArray(), hashes = Enumerable.Repeat(Hash4, 11).ToArray();
        var results = new bool[11];
        Assert.Equal(0, OnThisThread(() => Bcrypt.Verify(passwords, hashes, results)));
        Assert.All(results, Assert.True);
    }

    [Fact]
    public void EnhancedVerifyAllocatesNothing()
    {
        string hash = Bcrypt.EnhancedHash("password123", 4);
        string longPassword = new('é', 500), longHash = Bcrypt.EnhancedHash(longPassword, 4);
        Assert.Equal(0, OnThisThread(() => Bcrypt.EnhancedVerify("password123", hash)));
        Assert.Equal(0, OnThisThread(() => Bcrypt.EnhancedVerify(longPassword, longHash))); // pooled buffer
    }

    [Fact]
    public void HashAllocatesOnlyItsString()
    {
        long oneString = OnThisThread(() => GC.KeepAlive(new string('x', 60))) / Calls;
        Assert.Equal(oneString * Calls, OnThisThread(() => Bcrypt.Hash("password123", 4)));
        Assert.Equal(oneString * Calls, OnThisThread(() => Bcrypt.EnhancedHash("password123", 4)));
    }

    [Fact]
    public async Task QueuedVerifyAllocatesNothing()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        long least = long.MaxValue;
        for (int t = 0; t < Tries; t++)
        {
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < Calls; i++)
            {
                ValueTask<bool> a = q.VerifyAsync("password123", Hash4), b = q.VerifyAsync("wrong", Hash4), c = q.VerifyAsync("password123", Hash4);
                Assert.True(await a & !await b & await c);
            }
            if (t > 0) least = Math.Min(least, GC.GetTotalAllocatedBytes(precise: true) - before);
        }
        Assert.Equal(0, least);
    }

    [Fact]
    public async Task QueuedVerifyWithACancellableTokenAllocatesNothing()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        using var cts = new CancellationTokenSource();
        long least = long.MaxValue;
        for (int t = 0; t < Tries; t++)
        {
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < Calls; i++) Assert.True(await q.VerifyAsync("password123", Hash4, cts.Token));
            if (t > 0) least = Math.Min(least, GC.GetTotalAllocatedBytes(precise: true) - before);
        }
        Assert.Equal(0, least);
    }

    [Fact]
    public async Task QueuedHashAllocatesOnlyItsString()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        long oneString = OnThisThread(() => GC.KeepAlive(new string('x', 60))) / Calls;
        long least = long.MaxValue;
        for (int t = 0; t < Tries; t++)
        {
            long before = GC.GetTotalAllocatedBytes(precise: true);
            for (int i = 0; i < Calls; i++) GC.KeepAlive(await q.HashAsync("password123", 4));
            if (t > 0) least = Math.Min(least, GC.GetTotalAllocatedBytes(precise: true) - before);
        }
        Assert.Equal(oneString * Calls, least);
    }
}
