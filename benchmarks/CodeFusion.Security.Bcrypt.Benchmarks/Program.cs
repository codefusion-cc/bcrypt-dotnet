using System.Threading.Tasks;
using BenchmarkDotNet.Running;
using CodeFusion.Security.Benchmarks;

if (args.Length > 0 && args[0] == "throughput") return await Throughput.Run(args);
BenchmarkSwitcher.FromAssembly(typeof(VerifyBenchmarks).Assembly).Run(args);
return 0;
