using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace CodeFusion.Security.Benchmarks;

/// <summary>
/// Sign-ins a second with every processor busy, as a loaded server sees them: cost 10, one stored hash checked over
/// and over. Run with: dotnet run -c Release -f net10.0 --project benchmarks/CodeFusion.Security.Bcrypt.Benchmarks -- throughput [seconds]
/// </summary>
static class Throughput
{
    const string Password = "password123";
    // From Go's golang.org/x/crypto/bcrypt.
    const string Hash = "$2a$10$ZSfEoPvlcsj2XfvsSeK25em4NZ9Jm7ntGqXuLgQfHEeZPYB8899wq";
    static readonly TimeSpan Warmup = TimeSpan.FromSeconds(3);

    public static async Task<int> Run(string[] args)
    {
        double seconds = args.Length > 1 ? double.Parse(args[1], CultureInfo.InvariantCulture) : 20;
        var window = TimeSpan.FromSeconds(seconds);
        int cpus = Environment.ProcessorCount;
        Console.WriteLine($"{RuntimeInformation.FrameworkDescription}, {RuntimeInformation.ProcessArchitecture}, {cpus} logical processors; cost 10; {seconds:F0} s each after {Warmup.TotalSeconds:F0} s of warm-up");
        Report($"BCrypt.Net-Next, {cpus} threads", Threads(cpus, () => BCrypt.Net.BCrypt.Verify(Password, Hash), window));
        Report($"Bcrypt.Verify, {cpus} threads", Threads(cpus, () => Bcrypt.Verify(Password, Hash), window));
        foreach (int threads in cpus > 1 ? new[] { cpus / 2, cpus } : new[] { 1 })
            Report($"BcryptQueue, {threads} threads x 5 lanes", await Queue(threads, window));
        return 0;
    }

    static void Report(string name, double perSecond) => Console.WriteLine($"{name,-34} {perSecond,8:F1} checks/s");

    /// <summary>Checks a second with <paramref name="n"/> threads each checking in a loop.</summary>
    static double Threads(int n, Func<bool> check, TimeSpan window)
    {
        long count = 0;
        bool stop = false;
        var threads = new Thread[n];
        for (int i = 0; i < n; i++)
        {
            threads[i] = new Thread(() =>
            {
                while (!Volatile.Read(ref stop))
                {
                    if (!check()) throw new InvalidOperationException("a correct password failed");
                    Interlocked.Increment(ref count);
                }
            }) { IsBackground = true };
            threads[i].Start();
        }
        double rate = Measure(() => Interlocked.Read(ref count), window);
        Volatile.Write(ref stop, true);
        foreach (var t in threads) t.Join();
        return rate;
    }

    /// <summary>Checks a second through a queue kept full by twice as many callers as it has lanes.</summary>
    static async Task<double> Queue(int threads, TimeSpan window)
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = threads, MaxQueued = 1_000_000 });
        long count = 0;
        bool stop = false;
        var callers = new Task[threads * Bcrypt.MaxLanes * 2];
        for (int i = 0; i < callers.Length; i++)
            callers[i] = Task.Run(async () =>
            {
                while (!Volatile.Read(ref stop))
                {
                    if (!await q.VerifyAsync(Password, Hash)) throw new InvalidOperationException("a correct password failed");
                    Interlocked.Increment(ref count);
                }
            });
        double rate = await Task.Run(() => Measure(() => Interlocked.Read(ref count), window));
        Volatile.Write(ref stop, true);
        await Task.WhenAll(callers);
        return rate;
    }

    static double Measure(Func<long> count, TimeSpan window)
    {
        Thread.Sleep(Warmup);
        long start = count();
        var sw = Stopwatch.StartNew();
        Thread.Sleep(window);
        return (count() - start) / sw.Elapsed.TotalSeconds;
    }
}
