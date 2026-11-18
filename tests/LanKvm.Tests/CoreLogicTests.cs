using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using LanKvm.Core.Clipboard;
using LanKvm.Core.Input;
using LanKvm.Core.Native;
using LanKvm.Core.Network;
using LanKvm.Core.Update;
using LanKvm.Protocol;
using Xunit;

namespace LanKvm.Tests;

public class CoreLogicTests
{
    [Fact]
    public void Win32Structs_HaveExpectedNativeSizes()
    {
        int expectedInputSize = IntPtr.Size == 8 ? 40 : 28;
        Assert.Equal(expectedInputSize, Marshal.SizeOf<Win32Interop.INPUT>());

        int expectedRawHeaderSize = IntPtr.Size == 8 ? 24 : 16;
        Assert.Equal(expectedRawHeaderSize, Marshal.SizeOf<Win32Interop.RAWINPUTHEADER>());
        Assert.Equal(24, Marshal.SizeOf<Win32Interop.RAWMOUSE>());
    }

    [Fact]
    public void EdgeSwitchStateMachine_EnforcesResistanceAndCooldown_AcrossMultiMonitor()
    {
        var bounds = new ScreenRect(-1920, 0, 3840, 1080);
        var sm = new EdgeSwitchStateMachine(resistancePixels: 16, cooldownMs: 150);

        Assert.False(sm.TryShouldSwitchToClient(100, 540, 50, 0, bounds, ScreenEdge.Right, 200, out _));
        Assert.False(sm.TryShouldSwitchToClient(1919, 539, 10, 0, bounds, ScreenEdge.Right, 210, out _));
        Assert.False(sm.IsRemote);

        Assert.True(sm.TryShouldSwitchToClient(1919, 540, 8, 0, bounds, ScreenEdge.Right, 220, out float ratio));
        Assert.True(sm.IsRemote);
        Assert.InRange(ratio, 0.49f, 0.51f);

        sm.ResetToLocal(500);
        Assert.False(sm.TryShouldSwitchToClient(1919, 540, 30, 0, bounds, ScreenEdge.Right, 580, out _));
        Assert.True(sm.TryShouldSwitchToClient(1919, 540, 20, 0, bounds, ScreenEdge.Right, 700, out _));
    }

    [Fact]
    public void EdgeSwitchStateMachine_ClientReturnDetectsOppositeEdge()
    {
        var clientBounds = new ScreenRect(0, 0, 1920, 1080);
        var clientSm = new EdgeSwitchStateMachine(resistancePixels: 15, cooldownMs: 150);
        clientSm.ResetToLocal(100);

        Assert.False(clientSm.TryShouldReturnToHost(0, 270, -10, 0, clientBounds, ScreenEdge.Right, 300, out _));
        Assert.True(clientSm.TryShouldReturnToHost(0, 270, -8, 0, clientBounds, ScreenEdge.Right, 310, out float ratio));
        Assert.InRange(ratio, 0.24f, 0.26f);

        var (entryX, entryY) = EdgeSwitchStateMachine.ComputeEntryPoint(clientBounds, ScreenEdge.Left, 0.5f, insetPx: 8);
        Assert.Equal(8, entryX);
        Assert.InRange(entryY, 538, 541);
    }

    [Fact]
    public void ClipboardDeduplicator_PreventsRemotePingPongLoop()
    {
        var dedup = new ClipboardDeduplicator();
        byte[] remoteBytes = Encoding.UTF8.GetBytes("hello from host");
        byte[] localBytes = Encoding.UTF8.GetBytes("new local copy");

        dedup.MarkRemoteApplied(remoteBytes);
        Assert.True(dedup.ShouldSkipOutgoing(remoteBytes));
        Assert.False(dedup.ShouldSkipOutgoing(localBytes));
        Assert.True(dedup.ShouldSkipOutgoing(localBytes));
    }

    [Fact]
    public void NetworkHelper_IsPrivateOrLoopback_RejectsPublicIps()
    {
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Loopback));
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("192.168.1.50")));
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("192.168.0.12")));
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("10.0.1.5")));
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("172.16.0.1")));
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("172.31.255.254")));
        Assert.True(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("::ffff:192.168.1.50")));

        Assert.False(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("8.8.8.8")));
        Assert.False(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("1.1.1.1")));
        Assert.False(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("172.32.0.1")));
        Assert.False(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("172.15.255.255")));
        Assert.False(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("192.169.1.1")));
        Assert.False(NetworkHelper.IsPrivateOrLoopback(IPAddress.Parse("211.45.10.2")));
    }

    [Fact]
    public void DpapiHelper_RoundtripsToken_And_AppUpdaterComparesVersions()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        string encrypted = DpapiHelper.ProtectToBase64(secret);
        Assert.NotEqual(Convert.ToBase64String(secret), encrypted);

        byte[]? decrypted = DpapiHelper.TryUnprotectFromBase64(encrypted);
        Assert.Equal(secret, decrypted);
        Assert.Null(DpapiHelper.TryUnprotectFromBase64("not-valid-base64!!!"));

        Assert.True(AppUpdater.IsNewerVersion("v1.2.0", "1.1.0"));
        Assert.True(AppUpdater.IsNewerVersion("1.1.1", "1.1.0"));
        Assert.False(AppUpdater.IsNewerVersion("1.1.0", "1.1.0"));
        Assert.False(AppUpdater.IsNewerVersion("1.0.9", "1.1.0"));

        Assert.True(AppUpdater.IsValidGitHubRepo("owner/LanKvm"));
        Assert.False(AppUpdater.IsValidGitHubRepo("owner/../evil"));
        Assert.False(AppUpdater.IsValidGitHubRepo("owner/repo?foo=bar"));

        Assert.True(AppUpdater.IsTrustedGitHubDownloadUrl("https://github.com/owner/LanKvm/releases/download/v1.1.0/LanKvm.exe"));
        Assert.True(AppUpdater.IsTrustedGitHubDownloadUrl("https://objects.githubusercontent.com/github-production-release-asset/123/LanKvm.exe"));
        Assert.False(AppUpdater.IsTrustedGitHubDownloadUrl("http://github.com/owner/LanKvm/releases/download/v1.1.0/LanKvm.exe"));
        Assert.False(AppUpdater.IsTrustedGitHubDownloadUrl("https://evil.example.com/LanKvm.exe"));
    }

    [Fact]
    public void FileTransferService_BlocksPathTraversal_And_TransfersFilesSafely()
    {
        string sandbox = Path.Combine(Path.GetTempPath(), $"lankvm-ft-{Guid.NewGuid():N}");
        string srcRoot = Path.Combine(sandbox, "src");
        string subDir = Path.Combine(srcRoot, "MyFolder");
        Directory.CreateDirectory(subDir);

        try
        {
            Assert.Throws<InvalidDataException>(() => FileTransferService.ResolveSafeDestinationPath(sandbox, "../evil.exe"));
            Assert.Throws<InvalidDataException>(() => FileTransferService.ResolveSafeDestinationPath(sandbox, "a/../../evil.exe"));
            Assert.Throws<InvalidDataException>(() => FileTransferService.ResolveSafeDestinationPath(sandbox, @"C:\Windows\test.dll"));
            Assert.Throws<InvalidDataException>(() => FileTransferService.ResolveSafeDestinationPath(sandbox, @"\\server\share\a"));
            string safe = FileTransferService.ResolveSafeDestinationPath(sandbox, "MyFolder/nested.txt");
            Assert.StartsWith(Path.GetFullPath(sandbox), safe, StringComparison.OrdinalIgnoreCase);

            string file1 = Path.Combine(srcRoot, "hello.txt");
            string file2 = Path.Combine(subDir, "data.bin");
            File.WriteAllText(file1, "안녕하세요 LanKvm 파일 전송!");
            byte[] binData = RandomNumberGenerator.GetBytes(300_000);
            File.WriteAllBytes(file2, binData);

            Assert.True(FileTransferService.TryBuildTransfer([file1, subDir], out PreparedFileTransfer? prepared, out string? err));
            Assert.Null(err);
            Assert.NotNull(prepared);
            Assert.Equal(2, prepared!.Offer.Files.Count);

            using var incoming = new IncomingFileTransfer(prepared.Offer);
            var shaList = new List<string>();
            for (int idx = 0; idx < prepared.SourceFilePaths.Count; idx++)
            {
                byte[] all = File.ReadAllBytes(prepared.SourceFilePaths[idx]);
                shaList.Add(Convert.ToHexString(SHA256.HashData(all)));

                const int step = 100_000;
                for (int off = 0; off < all.Length; off += step)
                {
                    int len = Math.Min(step, all.Length - off);
                    incoming.WriteChunk(new FileTransferChunkPayload(prepared.Offer.TransferId, idx, off, all.AsSpan(off, len).ToArray()));
                }
            }

            IReadOnlyList<string> topPaths = incoming.FinalizeAndVerify(new FileTransferCompletePayload(prepared.Offer.TransferId, shaList));
            Assert.Equal(2, topPaths.Count);
            Assert.Equal("안녕하세요 LanKvm 파일 전송!", File.ReadAllText(topPaths[0]));
            Assert.Equal(binData, File.ReadAllBytes(Path.Combine(topPaths[1], "data.bin")));

            incoming.CleanupOnFailure();
        }
        finally
        {
            if (Directory.Exists(sandbox)) Directory.Delete(sandbox, recursive: true);
        }
    }

    [Fact]
    public void FullscreenDetector_ChecksMonitorCoverageCorrectly()
    {
        var mon = new Win32Interop.RECT { Left = 0, Top = 0, Right = 2560, Bottom = 1440 };
        var full = new Win32Interop.RECT { Left = 0, Top = 0, Right = 2560, Bottom = 1440 };
        var partial = new Win32Interop.RECT { Left = 100, Top = 100, Right = 2000, Bottom = 1200 };

        Assert.True(FullscreenDetector.IsWindowCoveringMonitor(full, mon));
        Assert.False(FullscreenDetector.IsWindowCoveringMonitor(partial, mon));
    }

    [Fact]
    public void SingleInstanceGuard_EnforcesSinglePrimary_And_SignalsActivation()
    {
        static bool RunOnFreshThread(Func<bool> func)
        {
            bool res = false;
            var t = new Thread(() => res = func()) { IsBackground = true };
            t.Start();
            t.Join();
            return res;
        }

        string suffix = Guid.NewGuid().ToString("N");
        string mutexName = $"Local\\LanKvmTestMutex_{suffix}";
        string eventName = $"Local\\LanKvmTestShow_{suffix}";

        using var activated = new ManualResetEventSlim(false);
        Assert.True(SingleInstanceGuard.TryAcquire(mutexName, eventName, [], false, null, out SingleInstanceGuard? guard1));
        Assert.NotNull(guard1);
        guard1!.RegisterActivationCallback(() => activated.Set());

        // Use dedicated OS threads because Win32 Mutex ownership is thread-reentrant.
        bool minAcquired = RunOnFreshThread(() =>
        {
            bool ok = SingleInstanceGuard.TryAcquire(mutexName, eventName, ["--minimized"], false, null, out SingleInstanceGuard? g);
            g?.Dispose();
            return ok;
        });
        Assert.False(minAcquired);
        Assert.False(activated.Wait(150));

        bool normalAcquired = RunOnFreshThread(() =>
        {
            bool ok = SingleInstanceGuard.TryAcquire(mutexName, eventName, [], true, null, out SingleInstanceGuard? g);
            g?.Dispose();
            return ok;
        });
        Assert.False(normalAcquired);
        Assert.True(activated.Wait(1500));

        guard1.Dispose();

        // Once disposed, a fresh instance can acquire the mutex again.
        bool reacquired = RunOnFreshThread(() =>
        {
            bool ok = SingleInstanceGuard.TryAcquire(mutexName, eventName, [], true, null, out SingleInstanceGuard? g);
            g?.Dispose();
            return ok;
        });
        Assert.True(reacquired);

        Assert.True(SingleInstanceGuard.TryParseWaitPid(["--wait-pid", "4242"], out int parsedPid));
        Assert.Equal(4242, parsedPid);
    }

    [Fact]
    public void FirewallScriptBuilder_ScopesProgram_And_RemovesRules()
    {
        string exeScript = NetworkHelper.BuildEnsureFirewallScript(24800, 24801, @"C:\Users\O'Connor\Apps\LanKvm.exe");
        Assert.Contains("LanKvm-TCP-24800", exeScript);
        Assert.Contains("LanKvm-UDP-24801", exeScript);
        Assert.Contains("-Program 'C:\\Users\\O''Connor\\Apps\\LanKvm.exe'", exeScript);
        Assert.Contains("LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", exeScript);

        string dotnetScript = NetworkHelper.BuildEnsureFirewallScript(24800, 24801, @"C:\Program Files\dotnet\dotnet.exe");
        Assert.DoesNotContain("-Program", dotnetScript);

        string removeScript = NetworkHelper.BuildRemoveFirewallScript();
        Assert.Contains("Remove-NetFirewallRule -DisplayName 'LanKvm-TCP-*','LanKvm-UDP-*'", removeScript);
    }
}
