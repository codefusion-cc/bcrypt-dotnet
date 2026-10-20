using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

// The tests read results the moment they are ready, synchronously, as the callers that hit the race did.
#pragma warning disable xUnit1031

namespace CodeFusion.Security.Tests;

/// <summary>
/// How a queued call completes. The runtime's ManualResetValueTaskSourceCore marks a result ready before it claims
/// the continuation slot; a caller that read the result in between and released the request had the completion land
/// in its next call, whose continuation then ran before its result existed. These tests pause the completing thread
/// right after the result is ready (a static hook, so they run alone) or oversubscribe the cores to widen that window.
/// </summary>
[Collection(nameof(Measuring))]
public class CompletionTests
{
    static readonly string Hash4 = Bcrypt.Hash("password123", 4);
    static readonly string SlowHash = Bcrypt.Hash("slow", 13);

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    static readonly AsyncLocal<string?> Local = new();

    static async Task<bool> AwaitIt(ValueTask<bool> check) => await check;

    /// <summary>Pauses the first completion after its result is ready, until <c>resume</c> is set.</summary>
    sealed class Pause : IDisposable
    {
        int _once;
        public readonly ManualResetEventSlim Paused = new(), Resume = new();

        public Pause() => CompletionCore.AfterReadyForTests = () =>
        {
            if (Interlocked.Exchange(ref _once, 1) != 0) return;
            Paused.Set();
            Resume.Wait(TimeSpan.FromSeconds(30));
        };

        public void Dispose()
        {
            CompletionCore.AfterReadyForTests = null;
            Resume.Set();
            Paused.Dispose();
            Resume.Dispose();
        }
    }

    [Fact]
    public async Task ACallerThatReadsAtOnceDoesNotGetTheCompletionInItsNextCall()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        using var pause = new Pause();
        var first = q.VerifyAsync("password123", Hash4, Ct);
        Assert.True(pause.Paused.Wait(TimeSpan.FromSeconds(10), Ct));

        // The completing thread has marked the result ready and stopped there. Read it, which frees the request.
        Assert.True(first.IsCompleted);
        Assert.True(first.GetAwaiter().GetResult());
        // The next call gets that request back and waits on it with a continuation.
        var next = q.VerifyAsync("slow", SlowHash, Ct);
        Assert.Same(Source(first), Source(next));
        var awaiting = AwaitIt(next);
        pause.Resume.Set();

        // Had the completion claimed the slot only now, it would have run that continuation before next's result.
        Assert.True(await awaiting);
    }

    [Fact]
    public async Task AContinuationRegisteredAfterCompletionRunsAtOnceOnItsOwnThread()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        using var pause = new Pause();
        var check = q.VerifyAsync("password123", Hash4, Ct);
        Assert.True(pause.Paused.Wait(TimeSpan.FromSeconds(10), Ct));

        // As an awaiter that looked just before the result came: it registers after completion.
        Thread? ranOn = null;
        check.GetAwaiter().UnsafeOnCompleted(() => ranOn = Thread.CurrentThread);
        Assert.Same(Thread.CurrentThread, ranOn); // inline, not queued to the pool
        pause.Resume.Set();
        Assert.True(check.GetAwaiter().GetResult());
    }

    /// <summary>
    /// Many callers each read their result the moment it is ready and queue their next call at once, which the pool
    /// most often hands the request just freed. With twice as many callers as cores, all spinning, and as many workers,
    /// the threads that complete calls are preempted often. The runtime's window is a few instructions, so this can't
    /// force it the way the paused test above does; it guards the whole path under load.
    /// </summary>
    [Fact]
    public void CallersReadingAtOnceGetTheirOwnResultsWithTheCoresOversubscribed()
    {
        int cores = Environment.ProcessorCount;
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = cores, Lanes = 2 });
        long rounds = 0, failures = 0;
        string? firstFailure = null;
        var stop = Stopwatch.StartNew();
        var callers = new Thread[cores * 2];
        for (int c = 0; c < callers.Length; c++)
        {
            int caller = c;
            callers[c] = new Thread(() =>
            {
                for (int i = 0; stop.Elapsed < TimeSpan.FromSeconds(2); i++)
                {
                    try
                    {
                        bool expected = (i + caller) % 2 == 0;
                        var spun = q.VerifyAsync(expected ? "password123" : "password124", Hash4);
                        while (!spun.IsCompleted) Thread.SpinWait(20); // read the moment it is ready
                        bool spunResult = spun.GetAwaiter().GetResult();
                        // At once, the next call: a continuation registered on what is likely the same request.
                        bool awaited = q.VerifyAsync(expected ? "password124" : "password123", Hash4).AsTask().GetAwaiter().GetResult();
                        if (spunResult != expected || awaited == expected) throw new InvalidOperationException("a caller got another call's result");
                        Interlocked.Increment(ref rounds);
                    }
                    catch (Exception e)
                    {
                        if (Interlocked.Increment(ref failures) == 1) firstFailure = e.ToString();
                    }
                }
            }) { IsBackground = true };
            callers[c].Start();
        }
        foreach (var t in callers) Assert.True(t.Join(TimeSpan.FromSeconds(60)));
        Assert.True(failures == 0, $"{failures} of {rounds + failures} rounds failed; the first: {firstFailure}");
        Assert.True(rounds > 100, $"only {rounds} rounds ran");
    }

    sealed class CountingContext : SynchronizationContext
    {
        public int Posts;

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref Posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }
    }

    [Fact]
    public async Task AnAwaitUnderASynchronizationContextResumesThere()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        var context = new CountingContext();
        var previous = SynchronizationContext.Current;
        Task<bool> awaiting;
        SynchronizationContext.SetSynchronizationContext(context);
        try { awaiting = AwaitIt(q.VerifyAsync("slow", SlowHash, Ct)); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
        Assert.True(await awaiting);
        Assert.Equal(1, context.Posts);
    }

    [Fact]
    public async Task OnCompletedFlowsTheExecutionContext()
    {
        using var q = new BcryptQueue(new BcryptQueueOptions { Threads = 1 });
        var check = q.VerifyAsync("slow", SlowHash, Ct);
        var seen = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Local.Value = "caller";
        check.GetAwaiter().OnCompleted(() => seen.SetResult(Local.Value));
        Local.Value = "changed";
        Assert.Equal("caller", await seen.Task);
        Assert.True(check.GetAwaiter().GetResult());
    }

    static object Source<T>(ValueTask<T> task) =>
        typeof(ValueTask<T>).GetField("_obj", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(task)!;
}
