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
}
