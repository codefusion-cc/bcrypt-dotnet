using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;

namespace CodeFusion.Security.Benchmarks;

/// <summary>
/// One check at cost 10, as a sign-in runs it. Interleaved and queued runs report the time per hash: n hashes run
/// together take n times the reported time.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class VerifyBenchmarks
{
    const string Password = "password123";
    // From Go's golang.org/x/crypto/bcrypt.
    const string Hash = "$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq";

    static readonly string[] Passwords = [Password, Password, Password, Password, Password];
    static readonly string[] Hashes = [Hash, Hash, Hash, Hash, Hash];
    readonly bool[] _results = new bool[Bcrypt.MaxLanes];
    BcryptQueue _queue = null!;

    [GlobalSetup]
    public void Setup() => _queue = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });

    [GlobalCleanup]
    public void Cleanup() => _queue.Dispose();

    [Benchmark(Baseline = true), BenchmarkCategory("verify")]
    public bool BCryptNetNext() => BCrypt.Net.BCrypt.Verify(Password, Hash);

    [Benchmark, BenchmarkCategory("verify")]
    public bool Verify() => Bcrypt.Verify(Password, Hash);

    [Benchmark(OperationsPerInvoke = 2), BenchmarkCategory("verify")]
    public bool Lanes2() => Lanes(2);

    [Benchmark(OperationsPerInvoke = 3), BenchmarkCategory("verify")]
    public bool Lanes3() => Lanes(3);

    [Benchmark(OperationsPerInvoke = 4), BenchmarkCategory("verify")]
    public bool Lanes4() => Lanes(4);

    [Benchmark(OperationsPerInvoke = 5), BenchmarkCategory("verify")]
    public bool Lanes5() => Lanes(5);

    /// <summary>Five sign-ins through the queue with one thread: they run as one 5-lane run.</summary>
    [Benchmark(OperationsPerInvoke = 5), BenchmarkCategory("verify")]
    public ValueTask<bool> Queue5() => FiveThroughTheQueue();

    // Its state machine is pooled, so only the queue's own allocations count. Not on Queue5 itself: BenchmarkDotNet
    // 0.16 copies a benchmark's attributes into generated code, and the open generic type doesn't compile there.
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    async ValueTask<bool> FiveThroughTheQueue()
    {
        ValueTask<bool> a = _queue.VerifyAsync(Password, Hash), b = _queue.VerifyAsync(Password, Hash), c = _queue.VerifyAsync(Password, Hash),
            d = _queue.VerifyAsync(Password, Hash), e = _queue.VerifyAsync(Password, Hash);
        return await a & await b & await c & await d & await e;
    }

    bool Lanes(int n)
    {
        Bcrypt.Verify(Passwords.AsSpan(0, n), Hashes.AsSpan(0, n), _results.AsSpan(0, n));
        return _results[n - 1];
    }
}

/// <summary>A new hash at cost 10: the string it returns is all it allocates.</summary>
[MemoryDiagnoser]
public class HashBenchmarks
{
    [Benchmark(Baseline = true)]
    public string BCryptNetNext() => BCrypt.Net.BCrypt.HashPassword("password123", 10);

    [Benchmark]
    public string Hash() => Bcrypt.Hash("password123", 10);

    [Benchmark]
    public string EnhancedHash() => Bcrypt.EnhancedHash("password123", 10);
}
