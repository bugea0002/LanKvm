using System.Security.Cryptography;
using LanKvm.Protocol;
using Xunit;

namespace LanKvm.Tests;

public class ProtocolTests
{
    [Fact]
    public async Task PacketCodec_RoundtripsAllControlFrames()
    {
        using var ms = new MemoryStream();

        byte[] sNonce = RandomNumberGenerator.GetBytes(32);
        byte[] cNonce = RandomNumberGenerator.GetBytes(32);
        byte[] hmac = RandomNumberGenerator.GetBytes(32);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] issuedToken = RandomNumberGenerator.GetBytes(32);

        await PacketCodec.WriteFrameAsync(ms, MessageType.PinChallenge,
            PacketCodec.EncodePinChallenge(new PinChallengePayload(12345UL, sNonce)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.PinResponse,
            PacketCodec.EncodePinResponse(new PinResponsePayload(AuthMode.DeviceToken, "cid-1", cNonce, hmac, "Laptop-한글", 1920, 1080)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.AuthResult,
            PacketCodec.EncodeAuthResult(new AuthResultPayload(true, 12345UL, key, "Desktop-PC", 2560, 1440, "OK", "cid-1", issuedToken, "1.1.0", "ABCD")));
        await PacketCodec.WriteFrameAsync(ms, MessageType.SwitchScreen,
            PacketCodec.EncodeSwitchScreen(new SwitchScreenPayload(true, ScreenEdge.Right, 0.42f)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.EdgeReturn,
            PacketCodec.EncodeEdgeReturn(new EdgeReturnPayload(ScreenEdge.Right, 0.75f)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.MouseButton,
            PacketCodec.EncodeMouseButton(new MouseButtonPayload(MouseButtonKind.XButton2, true)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.MouseWheel,
            PacketCodec.EncodeMouseWheel(new MouseWheelPayload(-120, true)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.KeyEvent,
            PacketCodec.EncodeKeyEvent(new KeyEventPayload(0x15, 0x72, true, false)));
        await PacketCodec.WriteFrameAsync(ms, MessageType.UdpMotionFallback,
            PacketCodec.EncodeUdpFallbackMotion(-14, 27));
        await PacketCodec.WriteFrameAsync(ms, MessageType.Heartbeat,
            PacketCodec.EncodeHeartbeat(987654321L));
        await PacketCodec.WriteFrameAsync(ms, MessageType.UpdateChunk,
            PacketCodec.EncodeUpdateChunk(new UpdateChunkPayload(1024, 4096, [1, 2, 3, 4])));
        await PacketCodec.WriteFrameAsync(ms, MessageType.UpdateComplete,
            PacketCodec.EncodeUpdateComplete("DEADBEEF"));
        await PacketCodec.WriteFrameAsync(ms, MessageType.FileOffer,
            PacketCodec.EncodeFileOffer(new FileOfferPayload(555UL, ["folder", "a.txt"], [new FileEntryInfo("folder/b.bin", 2048), new FileEntryInfo("a.txt", 12)])));
        await PacketCodec.WriteFrameAsync(ms, MessageType.FileTransferRequest,
            PacketCodec.EncodeFileTransferRequest(555UL));
        await PacketCodec.WriteFrameAsync(ms, MessageType.FileTransferChunk,
            PacketCodec.EncodeFileTransferChunk(new FileTransferChunkPayload(555UL, 1, 0, [9, 8, 7])));
        await PacketCodec.WriteFrameAsync(ms, MessageType.FileTransferComplete,
            PacketCodec.EncodeFileTransferComplete(new FileTransferCompletePayload(555UL, ["SHA1", "SHA2"])));

        ms.Position = 0;

        var f1 = await PacketCodec.ReadFrameAsync(ms);
        Assert.NotNull(f1);
        var p1 = PacketCodec.DecodePinChallenge(f1!.Payload);
        Assert.Equal(12345UL, p1.SessionId);
        Assert.Equal(sNonce, p1.ServerNonce);

        var f2 = await PacketCodec.ReadFrameAsync(ms);
        var p2 = PacketCodec.DecodePinResponse(f2!.Payload);
        Assert.Equal(AuthMode.DeviceToken, p2.Mode);
        Assert.Equal("cid-1", p2.ClientId);
        Assert.Equal("Laptop-한글", p2.ClientName);
        Assert.Equal(1920, p2.ScreenWidth);
        Assert.Equal(1080, p2.ScreenHeight);

        var f3 = await PacketCodec.ReadFrameAsync(ms);
        var p3 = PacketCodec.DecodeAuthResult(f3!.Payload);
        Assert.True(p3.Accepted);
        Assert.Equal(key, p3.UdpSessionKey);
        Assert.Equal("Desktop-PC", p3.HostName);
        Assert.Equal("cid-1", p3.IssuedClientId);
        Assert.Equal(issuedToken, p3.IssuedToken);
        Assert.Equal("1.1.0", p3.AppVersion);
        Assert.Equal("ABCD", p3.ExeSha256);

        var f4 = await PacketCodec.ReadFrameAsync(ms);
        var p4 = PacketCodec.DecodeSwitchScreen(f4!.Payload);
        Assert.True(p4.ToClient);
        Assert.Equal(ScreenEdge.Right, p4.EntryEdge);
        Assert.Equal(0.42f, p4.Ratio, 3);

        var f5 = await PacketCodec.ReadFrameAsync(ms);
        var p5 = PacketCodec.DecodeEdgeReturn(f5!.Payload);
        Assert.Equal(0.75f, p5.Ratio, 3);

        var f6 = await PacketCodec.ReadFrameAsync(ms);
        var p6 = PacketCodec.DecodeMouseButton(f6!.Payload);
        Assert.Equal(MouseButtonKind.XButton2, p6.Button);
        Assert.True(p6.IsDown);

        var f7 = await PacketCodec.ReadFrameAsync(ms);
        var p7 = PacketCodec.DecodeMouseWheel(f7!.Payload);
        Assert.Equal(-120, p7.Delta);
        Assert.True(p7.IsHorizontal);

        var f8 = await PacketCodec.ReadFrameAsync(ms);
        var p8 = PacketCodec.DecodeKeyEvent(f8!.Payload);
        Assert.Equal((ushort)0x15, p8.VirtualKey);
        Assert.Equal((ushort)0x72, p8.ScanCode);
        Assert.True(p8.IsExtended);
        Assert.False(p8.IsKeyUp);

        var f9 = await PacketCodec.ReadFrameAsync(ms);
        var p9 = PacketCodec.DecodeUdpFallbackMotion(f9!.Payload);
        Assert.Equal(-14, p9.Dx);
        Assert.Equal(27, p9.Dy);

        var f10 = await PacketCodec.ReadFrameAsync(ms);
        Assert.Equal(987654321L, PacketCodec.DecodeHeartbeat(f10!.Payload));

        var f11 = await PacketCodec.ReadFrameAsync(ms);
        var p11 = PacketCodec.DecodeUpdateChunk(f11!.Payload);
        Assert.Equal(1024, p11.Offset);
        Assert.Equal(4096, p11.TotalLength);
        Assert.Equal([1, 2, 3, 4], p11.Data);

        var f12 = await PacketCodec.ReadFrameAsync(ms);
        var p12 = PacketCodec.DecodeUpdateComplete(f12!.Payload);
        Assert.Equal("DEADBEEF", p12.Sha256Hex);

        var f13 = await PacketCodec.ReadFrameAsync(ms);
        var p13 = PacketCodec.DecodeFileOffer(f13!.Payload);
        Assert.Equal(555UL, p13.TransferId);
        Assert.Equal(["folder", "a.txt"], p13.TopLevelRelativePaths);
        Assert.Equal(2, p13.Files.Count);
        Assert.Equal("folder/b.bin", p13.Files[0].RelativePath);
        Assert.Equal(2048, p13.Files[0].Length);

        var f14 = await PacketCodec.ReadFrameAsync(ms);
        Assert.Equal(555UL, PacketCodec.DecodeFileTransferRequest(f14!.Payload).TransferId);

        var f15 = await PacketCodec.ReadFrameAsync(ms);
        var p15 = PacketCodec.DecodeFileTransferChunk(f15!.Payload);
        Assert.Equal(1, p15.FileIndex);
        Assert.Equal([9, 8, 7], p15.Data);

        var f16 = await PacketCodec.ReadFrameAsync(ms);
        var p16 = PacketCodec.DecodeFileTransferComplete(f16!.Payload);
        Assert.Equal(["SHA1", "SHA2"], p16.FileSha256HexList);

        Assert.Null(await PacketCodec.ReadFrameAsync(ms));
    }

    [Fact]
    public async Task MotionCoalescer_And_SubPixelAccumulator_PreserveExactDeltas()
    {
        using var coalescer = new MotionCoalescer();
        Parallel.For(0, 1000, _ => coalescer.AddDelta(2, -3));

        await coalescer.WaitForDataAsync(CancellationToken.None);
        Assert.True(coalescer.TryDrain(out int dx, out int dy));
        Assert.Equal(2000, dx);
        Assert.Equal(-3000, dy);
        Assert.False(coalescer.TryDrain(out _, out _));

        var acc = new SubPixelAccumulator();
        int sumX = 0;
        for (int i = 0; i < 10; i++)
        {
            var (sx, _) = acc.Scale(1, 0, 0.3);
            sumX += sx;
        }
        Assert.Equal(3, sumX);
    }

    [Fact]
    public void UdpMotionCrypto_EncryptsDecrypts_RejectsTamperAndReplay()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var hostCrypto = new UdpMotionCrypto(777UL, key);
        using var clientCrypto = new UdpMotionCrypto(777UL, key);

        byte[] hello = new byte[UdpMotionCrypto.HelloPacketSize];
        int hLen = clientCrypto.EncryptClientHello(424242L, hello);
        Assert.Equal(UdpMotionCrypto.HelloPacketSize, hLen);
        Assert.True(hostCrypto.TryDecryptClientHello(hello, out ulong sid, out long ticks));
        Assert.Equal(777UL, sid);
        Assert.Equal(424242L, ticks);

        Assert.False(hostCrypto.TryDecryptClientHello(hello, out _, out _));

        byte[] p1 = new byte[UdpMotionCrypto.MotionPacketSize];
        byte[] p2 = new byte[UdpMotionCrypto.MotionPacketSize];
        hostCrypto.EncryptMotionDelta(10, -5, 0, p1);
        hostCrypto.EncryptMotionDelta(-3, 8, 0, p2);

        Assert.True(clientCrypto.TryDecryptMotionDelta(p2, out _, out _, out int dx2, out int dy2, out _));
        Assert.Equal((-3, 8), (dx2, dy2));

        Assert.True(clientCrypto.TryDecryptMotionDelta(p1, out _, out _, out int dx1, out int dy1, out _));
        Assert.Equal((10, -5), (dx1, dy1));

        Assert.False(clientCrypto.TryDecryptMotionDelta(p1, out _, out _, out _, out _, out _));

        byte[] p3 = new byte[UdpMotionCrypto.MotionPacketSize];
        hostCrypto.EncryptMotionDelta(5, 5, 0, p3);
        p3[22] ^= 0xFF;
        Assert.False(clientCrypto.TryDecryptMotionDelta(p3, out _, out _, out _, out _, out _));
    }

    [Fact]
    public void TlsPairing_And_PinRateLimiter_WorkCorrectly()
    {
        byte[] sNonce = RandomNumberGenerator.GetBytes(32);
        byte[] cNonce = RandomNumberGenerator.GetBytes(32);
        string realFp = "AABBCCDD11223344";
        string attackerFp = "DEADBEEF00000000";

        byte[] hmac = TlsPairing.ComputePinHmac("482913", sNonce, cNonce, realFp);

        Assert.True(TlsPairing.VerifyPinHmac("482913", sNonce, cNonce, realFp, hmac));
        Assert.False(TlsPairing.VerifyPinHmac("000000", sNonce, cNonce, realFp, hmac));
        Assert.False(TlsPairing.VerifyPinHmac("482913", sNonce, cNonce, attackerFp, hmac));

        byte[] token = RandomNumberGenerator.GetBytes(32);
        string hashHex = TlsPairing.ComputeTokenHashHex(token);
        Assert.True(TlsPairing.VerifyTokenHashHex(token, hashHex));
        token[0] ^= 0xFF;
        Assert.False(TlsPairing.VerifyTokenHashHex(token, hashHex));

        var limiter = new PinRateLimiter(maxFailures: 5, lockoutDuration: TimeSpan.FromSeconds(60));
        var now = DateTimeOffset.UtcNow;
        for (int i = 0; i < 4; i++)
        {
            limiter.RecordFailure("192.168.0.5", now);
            Assert.False(limiter.IsLockedOut("192.168.0.5", now, out _));
        }

        limiter.RecordFailure("192.168.0.5", now);
        Assert.True(limiter.IsLockedOut("192.168.0.5", now.AddSeconds(10), out TimeSpan rem));
        Assert.True(rem.TotalSeconds >= 49);
        Assert.False(limiter.IsLockedOut("192.168.0.5", now.AddSeconds(61), out _));

        limiter.RecordFailure("192.168.0.6", now);
        limiter.RecordSuccess("192.168.0.6");
        Assert.False(limiter.IsLockedOut("192.168.0.6", now, out _));
    }
}
