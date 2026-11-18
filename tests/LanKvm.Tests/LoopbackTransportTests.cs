using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using LanKvm.Protocol;
using Xunit;

namespace LanKvm.Tests;

public class LoopbackTransportTests
{
    [Fact]
    public async Task TlsPinPairing_Then_TokenReconnect_And_EncryptedUdpMotion_WorkOverLoopback()
    {
        string tempCert = Path.Combine(Path.GetTempPath(), $"lankvm-test-{Guid.NewGuid():N}.pfx");
        try
        {
            using var cert = TlsPairing.CreateOrLoadHostCertificate(tempCert);
            string hostFp = TlsPairing.GetCertificateFingerprint(cert);
            const string pin = "654321";

            using var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            int tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;

            using var hostUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int udpPort = ((IPEndPoint)hostUdp.Client.LocalEndPoint!).Port;

            byte[] udpKey = RandomNumberGenerator.GetBytes(32);
            byte[] issuedRawToken = RandomNumberGenerator.GetBytes(32);
            string expectedTokenHash = TlsPairing.ComputeTokenHashHex(issuedRawToken);
            const string issuedClientId = "client-abc-123";
            const ulong sessionId = 999111UL;

            Task serverTask = Task.Run(async () =>
            {
                // Connection 1: 1st-time PIN pairing -> issues device token
                using (TcpClient accepted1 = await tcpListener.AcceptTcpClientAsync())
                using (var ssl1 = new SslStream(accepted1.GetStream(), false))
                {
                    await ssl1.AuthenticateAsServerAsync(cert, false, false);
                    using var transport1 = new FramedControlTransport(ssl1);

                    byte[] serverNonce = RandomNumberGenerator.GetBytes(32);
                    await transport1.SendAsync(MessageType.PinChallenge,
                        PacketCodec.EncodePinChallenge(new PinChallengePayload(sessionId, serverNonce)));

                    var resp = PacketCodec.DecodePinResponse((await transport1.ReceiveAsync())!.Payload);
                    Assert.Equal(AuthMode.PinPairing, resp.Mode);
                    Assert.True(TlsPairing.VerifyPinHmac(pin, serverNonce, resp.ClientNonce, hostFp, resp.Credential));

                    await transport1.SendAsync(MessageType.AuthResult,
                        PacketCodec.EncodeAuthResult(new AuthResultPayload(
                            true, sessionId, udpKey, "HostBox", 2560, 1440, "OK",
                            issuedClientId, issuedRawToken, "1.1.0", "SHA")));
                }

                // Connection 2: Automatic DeviceToken auth WITHOUT PIN
                using (TcpClient accepted2 = await tcpListener.AcceptTcpClientAsync())
                using (var ssl2 = new SslStream(accepted2.GetStream(), false))
                {
                    await ssl2.AuthenticateAsServerAsync(cert, false, false);
                    using var transport2 = new FramedControlTransport(ssl2);

                    byte[] serverNonce2 = RandomNumberGenerator.GetBytes(32);
                    await transport2.SendAsync(MessageType.PinChallenge,
                        PacketCodec.EncodePinChallenge(new PinChallengePayload(sessionId + 1, serverNonce2)));

                    var resp2 = PacketCodec.DecodePinResponse((await transport2.ReceiveAsync())!.Payload);
                    Assert.Equal(AuthMode.DeviceToken, resp2.Mode);
                    Assert.Equal(issuedClientId, resp2.ClientId);
                    Assert.True(TlsPairing.VerifyTokenHashHex(resp2.Credential, expectedTokenHash));

                    await transport2.SendAsync(MessageType.AuthResult,
                        PacketCodec.EncodeAuthResult(new AuthResultPayload(
                            true, sessionId + 1, udpKey, "HostBox", 2560, 1440, "OK")));

                    using var crypto = new UdpMotionCrypto(sessionId + 1, udpKey);
                    UdpReceiveResult hello = await hostUdp.ReceiveAsync();
                    Assert.True(crypto.TryDecryptClientHello(hello.Buffer, out ulong sid, out _));
                    Assert.Equal(sessionId + 1, sid);

                    byte[] motionBuf = new byte[UdpMotionCrypto.MotionPacketSize];
                    int len = crypto.EncryptMotionDelta(25, -15, 0, motionBuf);
                    await hostUdp.SendAsync(motionBuf.AsMemory(0, len), hello.RemoteEndPoint);
                }
            });

            // Client Conn 1 (PIN Pairing)
            string? savedId;
            byte[]? savedToken;
            using (var clientTcp1 = new TcpClient())
            {
                await clientTcp1.ConnectAsync(IPAddress.Loopback, tcpPort);
                string? observedFp = null;
                using var clientSsl1 = new SslStream(clientTcp1.GetStream(), false, (_, c, _, _) =>
                {
                    observedFp = TlsPairing.GetCertificateFingerprint(c!);
                    return true;
                });
                await clientSsl1.AuthenticateAsClientAsync("127.0.0.1");

                using var ct1 = new FramedControlTransport(clientSsl1);
                var ch = PacketCodec.DecodePinChallenge((await ct1.ReceiveAsync())!.Payload);
                byte[] cn = RandomNumberGenerator.GetBytes(32);
                byte[] hmac = TlsPairing.ComputePinHmac(pin, ch.ServerNonce, cn, observedFp!);
                await ct1.SendAsync(MessageType.PinResponse,
                    PacketCodec.EncodePinResponse(new PinResponsePayload(AuthMode.PinPairing, string.Empty, cn, hmac, "ClientLaptop", 1920, 1080)));

                var auth1 = PacketCodec.DecodeAuthResult((await ct1.ReceiveAsync())!.Payload);
                Assert.True(auth1.Accepted);
                savedId = auth1.IssuedClientId;
                savedToken = auth1.IssuedToken;
                Assert.Equal(issuedClientId, savedId);
                Assert.Equal(issuedRawToken, savedToken);
            }

            // Client Conn 2 (Zero-PIN DeviceToken Reconnect + UDP Motion)
            using (var clientTcp2 = new TcpClient())
            {
                await clientTcp2.ConnectAsync(IPAddress.Loopback, tcpPort);
                using var clientSsl2 = new SslStream(clientTcp2.GetStream(), false, (_, _, _, _) => true);
                await clientSsl2.AuthenticateAsClientAsync("127.0.0.1");

                using var ct2 = new FramedControlTransport(clientSsl2);
                _ = PacketCodec.DecodePinChallenge((await ct2.ReceiveAsync())!.Payload);
                byte[] cn2 = RandomNumberGenerator.GetBytes(32);
                await ct2.SendAsync(MessageType.PinResponse,
                    PacketCodec.EncodePinResponse(new PinResponsePayload(AuthMode.DeviceToken, savedId!, cn2, savedToken!, "ClientLaptop", 1920, 1080)));

                var auth2 = PacketCodec.DecodeAuthResult((await ct2.ReceiveAsync())!.Payload);
                Assert.True(auth2.Accepted);

                using var clientUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                using var clientCrypto = new UdpMotionCrypto(auth2.SessionId, auth2.UdpSessionKey);

                byte[] helloBuf = new byte[UdpMotionCrypto.HelloPacketSize];
                int hLen = clientCrypto.EncryptClientHello(12345L, helloBuf);
                await clientUdp.SendAsync(helloBuf.AsMemory(0, hLen), new IPEndPoint(IPAddress.Loopback, udpPort));

                UdpReceiveResult motionRes = await clientUdp.ReceiveAsync();
                Assert.True(clientCrypto.TryDecryptMotionDelta(motionRes.Buffer, out _, out _, out int dx, out int dy, out _));
                Assert.Equal((25, -15), (dx, dy));
            }

            await serverTask;
        }
        finally
        {
            if (File.Exists(tempCert)) File.Delete(tempCert);
        }
    }

    [Fact]
    public async Task TlsPinHandshake_RejectsWrongPinOverLoopback()
    {
        string tempCert = Path.Combine(Path.GetTempPath(), $"lankvm-badpin-{Guid.NewGuid():N}.pfx");
        try
        {
            using var cert = TlsPairing.CreateOrLoadHostCertificate(tempCert);
            string hostFp = TlsPairing.GetCertificateFingerprint(cert);

            using var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            int tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;

            Task serverTask = Task.Run(async () =>
            {
                using TcpClient accepted = await tcpListener.AcceptTcpClientAsync();
                using var ssl = new SslStream(accepted.GetStream(), false);
                await ssl.AuthenticateAsServerAsync(cert, false, false);

                using var transport = new FramedControlTransport(ssl);
                byte[] serverNonce = RandomNumberGenerator.GetBytes(32);
                await transport.SendAsync(MessageType.PinChallenge,
                    PacketCodec.EncodePinChallenge(new PinChallengePayload(123UL, serverNonce)));

                var resp = PacketCodec.DecodePinResponse((await transport.ReceiveAsync())!.Payload);
                bool ok = TlsPairing.VerifyPinHmac("111111", serverNonce, resp.ClientNonce, hostFp, resp.Credential);
                Assert.False(ok);

                await transport.SendAsync(MessageType.AuthResult,
                    PacketCodec.EncodeAuthResult(new AuthResultPayload(false, 0, Array.Empty<byte>(), "HostBox", 0, 0, "Bad PIN")));
            });

            using var clientTcp = new TcpClient();
            await clientTcp.ConnectAsync(IPAddress.Loopback, tcpPort);
            string? observedFp = null;
            using var clientSsl = new SslStream(clientTcp.GetStream(), false, (_, c, _, _) =>
            {
                observedFp = TlsPairing.GetCertificateFingerprint(c!);
                return true;
            });
            await clientSsl.AuthenticateAsClientAsync("127.0.0.1");

            using var clientTransport = new FramedControlTransport(clientSsl);
            var challenge = PacketCodec.DecodePinChallenge((await clientTransport.ReceiveAsync())!.Payload);
            byte[] clientNonce = RandomNumberGenerator.GetBytes(32);
            byte[] wrongHmac = TlsPairing.ComputePinHmac("999999", challenge.ServerNonce, clientNonce, observedFp!);
            await clientTransport.SendAsync(MessageType.PinResponse,
                PacketCodec.EncodePinResponse(new PinResponsePayload(AuthMode.PinPairing, string.Empty, clientNonce, wrongHmac, "ClientLaptop", 1920, 1080)));

            var auth = PacketCodec.DecodeAuthResult((await clientTransport.ReceiveAsync())!.Payload);
            Assert.False(auth.Accepted);
            Assert.Equal("Bad PIN", auth.Reason);

            await serverTask;
        }
        finally
        {
            if (File.Exists(tempCert)) File.Delete(tempCert);
        }
    }
}
