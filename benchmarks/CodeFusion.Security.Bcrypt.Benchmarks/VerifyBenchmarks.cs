using System;
using System.Runtime.CompilerServices;
using System.Text;
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

    static readonly byte[] PasswordUtf8 = Encoding.UTF8.GetBytes(Password), HashAscii = Encoding.ASCII.GetBytes(Hash);
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

    /// <summary>The same check from bytes, as a server reads them off the wire.</summary>
    [Benchmark, BenchmarkCategory("verify")]
    public bool VerifyUtf8() => Bcrypt.Verify(PasswordUtf8, HashAscii);

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

    /// <summary><see cref="Queue5"/> through the byte overload.</summary>
    [Benchmark(OperationsPerInvoke = 5), BenchmarkCategory("verify")]
    public ValueTask<bool> Queue5Utf8() => FiveUtf8ThroughTheQueue();

    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    async ValueTask<bool> FiveUtf8ThroughTheQueue()
    {
        ValueTask<bool> a = _queue.VerifyAsync(PasswordUtf8, HashAscii), b = _queue.VerifyAsync(PasswordUtf8, HashAscii),
            c = _queue.VerifyAsync(PasswordUtf8, HashAscii), d = _queue.VerifyAsync(PasswordUtf8, HashAscii), e = _queue.VerifyAsync(PasswordUtf8, HashAscii);
        return await a & await b & await c & await d & await e;
    }

    bool Lanes(int n)
    {
        Bcrypt.Verify(Passwords.AsSpan(0, n), Hashes.AsSpan(0, n), _results.AsSpan(0, n));
        return _results[n - 1];
    }
}

/// <summary>A new hash at cost 10: the string overloads allocate only the string they return, the byte ones nothing.</summary>
[MemoryDiagnoser]
public class HashBenchmarks
{
    static readonly byte[] PasswordUtf8 = "password123"u8.ToArray();
    readonly byte[] _destination = new byte[Bcrypt.HashLength];
    BcryptQueue _queue = null!;

    [GlobalSetup]
    public void Setup() => _queue = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });

    [GlobalCleanup]
    public void Cleanup() => _queue.Dispose();

    [Benchmark(Baseline = true)]
    public string BCryptNetNext() => BCrypt.Net.BCrypt.HashPassword("password123", 10);

    [Benchmark]
    public string Hash() => Bcrypt.Hash("password123", 10);

    [Benchmark]
    public int HashUtf8() => Bcrypt.Hash(PasswordUtf8, 10, _destination);

    [Benchmark]
    public string EnhancedHash() => Bcrypt.EnhancedHash("password123", 10);

    [Benchmark]
    public ValueTask<string> QueueHash() => _queue.HashAsync("password123", 10);

    [Benchmark]
    public ValueTask<BcryptHash> QueueHashUtf8() => _queue.HashAsync(PasswordUtf8, 10);
}
