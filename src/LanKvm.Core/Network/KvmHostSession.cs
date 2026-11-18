using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using LanKvm.Core.Clipboard;
using LanKvm.Core.Input;
using LanKvm.Core.Update;
using LanKvm.Protocol;

namespace LanKvm.Core.Network;

public sealed record HostStatusSnapshot(
    bool IsListening,
    bool IsClientConnected,
    bool IsRemoteControlling,
    bool IsUdpActive,
    bool IsPinPairingOpen,
    int PairedDeviceCount,
    string ClientName,
    string ClientEndpoint,
    int RttMs,
    string Pin,
    string CertFingerprintShort,
    string StatusMessage);

/// <summary>
/// Hosts the KVM server: listens on TCP (TLS + DeviceToken/PIN) and UDP (AES-GCM motion),
/// enforces private-subnet filtering and PIN rate-limiting, captures local input via
/// HostInputEngine when controlling the client, and can stream self-updates over TLS.
/// </summary>
public sealed class KvmHostSession : IDisposable
{
    private readonly int _tcpPort;
    private readonly int _udpPort;
    private readonly X509Certificate2 _certificate;
    private readonly string _certFingerprintHex;
    private readonly MotionCoalescer _coalescer = new();
    private readonly HostInputEngine _inputEngine;
    private readonly ClipboardSyncService _clipboard;
    private readonly PinRateLimiter _rateLimiter = new(maxFailures: 5, lockoutDuration: TimeSpan.FromSeconds(60));
    private readonly SemaphoreSlim _unauthLimiter = new(3, 3);
    private readonly CancellationTokenSource _cts = new();

    private readonly object _trustedGate = new();
    private readonly List<TrustedClientRecord> _trustedClients;
    private readonly (bool CanServeSelf, string Version, string Sha256, string ExePath) _selfInfo;

    private TcpListener? _tcpListener;
    private UdpClient? _udpSocket;

    private readonly object _sessionGate = new();
    private ActiveClientContext? _activeClient;
    private string _pin;
    private DateTimeOffset? _pairingWindowUntil;
    private volatile bool _allowPrivateNetworksOnly;
    private bool _disposed;

    public event Action<HostStatusSnapshot>? StatusChanged;
    public event Action<TrustedClientRecord>? TrustedClientAdded;
    public event Action<string>? LogMessage;

    public KvmHostSession(
        int tcpPort,
        int udpPort,
        string certPath,
        ScreenEdge switchEdge,
        int edgeResistancePx,
        bool clipboardEnabled,
        bool allowPrivateNetworksOnly,
        IEnumerable<TrustedClientRecord>? initialTrustedClients = null)
    {
        _tcpPort = tcpPort;
        _udpPort = udpPort;
        _allowPrivateNetworksOnly = allowPrivateNetworksOnly;
        _certificate = TlsPairing.CreateOrLoadHostCertificate(certPath);
        _certFingerprintHex = TlsPairing.GetCertificateFingerprint(_certificate);
        _pin = TlsPairing.GenerateSixDigitPin();
        _trustedClients = initialTrustedClients?.ToList() ?? new List<TrustedClientRecord>();
        _selfInfo = AppUpdater.GetSelfExecutableInfo();

        _inputEngine = new HostInputEngine(_coalescer, edgeResistancePx);
        _inputEngine.SwitchEdge = switchEdge;
        _inputEngine.RemoteStateChanged += _ => PublishStatus();
        _inputEngine.CursorRepositionBlocked += () =>
            Log("커서 위치 복원이 Windows 권한(UIPI)에 의해 차단되었습니다. 우측 상단 '관리자 권한 재시작'을 사용해 주세요.");
        _inputEngine.EmergencyEscapeTriggered += () =>
        {
            Log("긴급 탈출 단축키(Ctrl+Alt+Esc)로 데스크탑 제어권을 복구했습니다.");
            _ = SendReleaseAllAsync();
            PublishStatus();
        };

        _clipboard = new ClipboardSyncService(OnLocalClipboardChangedAsync)
        {
            Enabled = clipboardEnabled
        };
    }

    public string CurrentPin => _pin;
    public string CertFingerprintShort => TlsPairing.FormatFingerprintShort(_certFingerprintHex);

    public bool IsPinPairingOpen
    {
        get
        {
            lock (_trustedGate)
            {
                if (_trustedClients.Count == 0) return true;
                return _pairingWindowUntil.HasValue && _pairingWindowUntil.Value > DateTimeOffset.UtcNow;
            }
        }
    }

    public ScreenEdge SwitchEdge
    {
        get => _inputEngine.SwitchEdge;
        set => _inputEngine.SwitchEdge = value;
    }

    public bool ClipboardEnabled
    {
        get => _clipboard.Enabled;
        set => _clipboard.Enabled = value;
    }

    public bool AllowPrivateNetworksOnly
    {
        get => _allowPrivateNetworksOnly;
        set => _allowPrivateNetworksOnly = value;
    }

    public void OpenPairingWindow(TimeSpan? duration = null)
    {
        _pin = TlsPairing.GenerateSixDigitPin();
        _pairingWindowUntil = DateTimeOffset.UtcNow + (duration ?? TimeSpan.FromMinutes(3));
        Log($"새 기기 페어링 창 열림 (3분간 유효, PIN: {_pin})");
        PublishStatus();
    }

    public void ClosePairingWindow()
    {
        _pairingWindowUntil = null;
        _pin = TlsPairing.GenerateSixDigitPin();
        PublishStatus();
    }

    public void ClearTrustedClients()
    {
        lock (_trustedGate)
        {
            _trustedClients.Clear();
        }
        _pairingWindowUntil = null;
        _pin = TlsPairing.GenerateSixDigitPin();
        Log("등록된 모든 신뢰 기기를 초기화했습니다. PIN 페어링이 열립니다.");
        PublishStatus();
    }

    public void RegeneratePin()
    {
        _pin = TlsPairing.GenerateSixDigitPin();
        if (GetTrustedCount() > 0)
        {
            _pairingWindowUntil = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(3);
        }
        Log($"새 PIN 생성됨: {_pin}");
        PublishStatus();
    }

    public void ForceReturnToLocal()
    {
        _inputEngine.ForceReturnToLocal(0.5f);
        _ = SendReleaseAllAsync();
        PublishStatus();
    }

    public void Start()
    {
        _tcpListener = new TcpListener(IPAddress.Any, _tcpPort);
        _tcpListener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _tcpListener.Start();

        _udpSocket = new UdpClient(new IPEndPoint(IPAddress.Any, _udpPort));
        NetworkHelper.DisableUdpConnReset(_udpSocket.Client);

        _inputEngine.Start();
        _clipboard.Start();

        _ = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _ = Task.Run(() => UdpReceiveLoopAsync(_cts.Token));
        _ = Task.Run(() => MotionSendLoopAsync(_cts.Token));
        _ = Task.Run(() => ControlEventPumpLoopAsync(_cts.Token));

        string modeLabel = IsPinPairingOpen ? "최초 페어링 대기" : $"등록 기기 {GetTrustedCount()}대 자동 접속 대기";
        Log($"Host 시작됨 (TCP :{_tcpPort}, UDP :{_udpPort}, {modeLabel}, v{_selfInfo.Version})");
        PublishStatus("노트북 연결 대기 중");
    }

    private int GetTrustedCount()
    {
        lock (_trustedGate) return _trustedClients.Count;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _tcpListener is not null)
        {
            TcpClient? tcp = null;
            try
            {
                tcp = await _tcpListener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                tcp.NoDelay = true;

                IPAddress remoteIp = ((IPEndPoint)tcp.Client.RemoteEndPoint!).Address;
                if (_allowPrivateNetworksOnly && !NetworkHelper.IsPrivateOrLoopback(remoteIp))
                {
                    Log($"[보안 차단] 외부 공인 IP 연결 시도 거절: {remoteIp}");
                    tcp.Dispose();
                    continue;
                }

                if (!await _unauthLimiter.WaitAsync(TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false))
                {
                    Log($"[보안 제한] 동시 미인증 연결 초과 — 거절: {remoteIp}");
                    tcp.Dispose();
                    continue;
                }

                _ = Task.Run(async () =>
                {
                    bool slotReleased = false;
                    try
                    {
                        await HandleClientAsync(tcp, () =>
                        {
                            if (!slotReleased)
                            {
                                slotReleased = true;
                                _unauthLimiter.Release();
                            }
                        }, ct).ConfigureAwait(false);
                    }
                    finally
                    {
                        if (!slotReleased)
                        {
                            _unauthLimiter.Release();
                        }
                    }
                }, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                tcp?.Dispose();
                Log($"연결 수락 오류: {ex.Message}");
                await Task.Delay(300, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(TcpClient tcp, Action releaseAuthSlot, CancellationToken outerCt)
    {
        string remoteEp = tcp.Client.RemoteEndPoint?.ToString() ?? "unknown";
        string remoteIpKey = ((IPEndPoint)tcp.Client.RemoteEndPoint!).Address.ToString();
        Log($"클라이언트 접속 시도: {remoteEp}");

        SslStream? ssl = null;
        FramedControlTransport? transport = null;
        ActiveClientContext? ctx = null;

        try
        {
            ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            using (var authCts = CancellationTokenSource.CreateLinkedTokenSource(outerCt))
            {
                authCts.CancelAfter(TimeSpan.FromSeconds(10));
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        ClientCertificateRequired = false,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                    },
                    authCts.Token).ConfigureAwait(false);
            }

            transport = new FramedControlTransport(ssl);
            ulong sessionId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
            byte[] serverNonce = RandomNumberGenerator.GetBytes(32);

            await transport.SendAsync(
                MessageType.PinChallenge,
                PacketCodec.EncodePinChallenge(new PinChallengePayload(sessionId, serverNonce)),
                outerCt).ConfigureAwait(false);

            ControlFrame? frame;
            using (var pinCts = CancellationTokenSource.CreateLinkedTokenSource(outerCt))
            {
                pinCts.CancelAfter(TimeSpan.FromSeconds(15));
                frame = await transport.ReceiveAsync(pinCts.Token).ConfigureAwait(false);
            }

            if (frame is null || frame.Type != MessageType.PinResponse)
            {
                Log($"인증 프로토콜 오류 ({remoteEp})");
                return;
            }

            if (_rateLimiter.IsLockedOut(remoteIpKey, DateTimeOffset.UtcNow, out TimeSpan remaining))
            {
                int sec = Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
                Log($"[보안 잠금] 반복 실패 IP 차단 중 ({remoteIpKey}, {sec}초 남음)");
                await transport.SendAsync(
                    MessageType.AuthResult,
                    PacketCodec.EncodeAuthResult(new AuthResultPayload(
                        false, 0, Array.Empty<byte>(), Environment.MachineName, 0, 0,
                        $"인증 시도 횟수 초과. {sec}초 후 다시 시도하세요.")),
                    outerCt).ConfigureAwait(false);
                return;
            }

            PinResponsePayload resp = PacketCodec.DecodePinResponse(frame.Payload);
            string issuedClientId = string.Empty;
            byte[] issuedRawToken = Array.Empty<byte>();

            if (resp.Mode == AuthMode.DeviceToken)
            {
                TrustedClientRecord? matched;
                lock (_trustedGate)
                {
                    matched = _trustedClients.FirstOrDefault(c =>
                        string.Equals(c.ClientId, resp.ClientId, StringComparison.Ordinal));
                }

                if (matched is null || !TlsPairing.VerifyTokenHashHex(resp.Credential, matched.TokenHashHex))
                {
                    _rateLimiter.RecordFailure(remoteIpKey, DateTimeOffset.UtcNow);
                    Log($"등록 기기 토큰 인증 실패 ({resp.ClientName} @ {remoteEp})");
                    await transport.SendAsync(
                        MessageType.AuthResult,
                        PacketCodec.EncodeAuthResult(new AuthResultPayload(
                            false, 0, Array.Empty<byte>(), Environment.MachineName, 0, 0,
                            "DEVICE_TOKEN_INVALID: 등록된 기기 정보가 유효하지 않습니다. PIN으로 다시 페어링하세요.")),
                        outerCt).ConfigureAwait(false);
                    return;
                }

                _rateLimiter.RecordSuccess(remoteIpKey);
                Log($"등록 기기 자동 인증 성공: {resp.ClientName} ({remoteEp})");
            }
            else
            {
                if (!IsPinPairingOpen)
                {
                    Log($"[보안 거절] PIN 페어링 잠금 상태에서 PIN 접속 시도 ({resp.ClientName} @ {remoteEp})");
                    await transport.SendAsync(
                        MessageType.AuthResult,
                        PacketCodec.EncodeAuthResult(new AuthResultPayload(
                            false, 0, Array.Empty<byte>(), Environment.MachineName, 0, 0,
                            "현재 PIN 페어링이 잠겨 있습니다. 데스크탑에서 '새 기기 페어링'을 누른 뒤 시도하세요.")),
                        outerCt).ConfigureAwait(false);
                    return;
                }

                if (!TlsPairing.VerifyPinHmac(_pin, serverNonce, resp.ClientNonce, _certFingerprintHex, resp.Credential))
                {
                    _rateLimiter.RecordFailure(remoteIpKey, DateTimeOffset.UtcNow);
                    Log($"PIN 인증 실패 ({resp.ClientName} @ {remoteEp})");
                    await transport.SendAsync(
                        MessageType.AuthResult,
                        PacketCodec.EncodeAuthResult(new AuthResultPayload(
                            false, 0, Array.Empty<byte>(), Environment.MachineName, 0, 0,
                            "PIN 번호가 일치하지 않습니다.")),
                        outerCt).ConfigureAwait(false);
                    return;
                }

                _rateLimiter.RecordSuccess(remoteIpKey);
                issuedClientId = Guid.NewGuid().ToString("N");
                issuedRawToken = RandomNumberGenerator.GetBytes(32);
                var record = new TrustedClientRecord(
                    issuedClientId,
                    resp.ClientName,
                    TlsPairing.ComputeTokenHashHex(issuedRawToken),
                    DateTimeOffset.UtcNow);

                lock (_trustedGate)
                {
                    _trustedClients.Add(record);
                }
                _pairingWindowUntil = null;
                TrustedClientAdded?.Invoke(record);
                Log($"신규 기기 페어링 완료: {resp.ClientName} (이후 PIN 없이 자동 연결됩니다)");
            }

            releaseAuthSlot();

            byte[] udpKey = RandomNumberGenerator.GetBytes(32);
            var primary = Screen.PrimaryScreen?.Bounds ?? new System.Drawing.Rectangle(0, 0, 1920, 1080);

            await transport.SendAsync(
                MessageType.AuthResult,
                PacketCodec.EncodeAuthResult(new AuthResultPayload(
                    true,
                    sessionId,
                    udpKey,
                    Environment.MachineName,
                    primary.Width,
                    primary.Height,
                    "OK",
                    issuedClientId,
                    issuedRawToken,
                    _selfInfo.Version,
                    _selfInfo.Sha256)),
                outerCt).ConfigureAwait(false);

            var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(outerCt);
            ctx = new ActiveClientContext(
                sessionId,
                resp.ClientName,
                remoteEp,
                tcp,
                ssl,
                transport,
                new UdpMotionCrypto(sessionId, udpKey),
                sessionCts);

            ActiveClientContext? previous;
            lock (_sessionGate)
            {
                previous = _activeClient;
                _activeClient = ctx;
            }
            previous?.Dispose();

            _inputEngine.CanSwitchToRemote = true;
            PublishStatus($"{resp.ClientName} 연결됨");

            var hbTask = Task.Run(() => HeartbeatLoopAsync(ctx), ctx.Cts.Token);
            try
            {
                await ReceiveLoopAsync(ctx).ConfigureAwait(false);
            }
            finally
            {
                ctx.Cts.Cancel();
                try { await hbTask.ConfigureAwait(false); } catch (OperationCanceledException) { }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            Log($"세션 종료 ({remoteEp}): {ex.Message}");
        }
        finally
        {
            bool wasActive = false;
            if (ctx is not null)
            {
                lock (_sessionGate)
                {
                    if (ReferenceEquals(_activeClient, ctx))
                    {
                        _activeClient = null;
                        wasActive = true;
                    }
                }
                ctx.Dispose();
            }
            else
            {
                transport?.Dispose();
                ssl?.Dispose();
                tcp.Dispose();
            }

            if (wasActive)
            {
                _inputEngine.CanSwitchToRemote = false;
                _inputEngine.ForceReturnToLocal(0.5f);
                PublishStatus("노트북 연결 끊김 — 로컬 제어 복구됨");
            }
        }
    }

    private async Task ReceiveLoopAsync(ActiveClientContext ctx)
    {
        while (!ctx.Cts.Token.IsCancellationRequested)
        {
            ControlFrame? frame = await ctx.Transport.ReceiveAsync(ctx.Cts.Token).ConfigureAwait(false);
            if (frame is null) break;

            switch (frame.Type)
            {
                case MessageType.EdgeReturn:
                {
                    var ret = PacketCodec.DecodeEdgeReturn(frame.Payload);
                    _inputEngine.ForceReturnToLocal(ret.Ratio);
                    PublishStatus();
                    break;
                }
                case MessageType.HeartbeatAck:
                {
                    long sentTs = PacketCodec.DecodeHeartbeat(frame.Payload);
                    double rttMs = (Stopwatch.GetTimestamp() - sentTs) * 1000.0 / Stopwatch.Frequency;
                    ctx.LastAckTicks = Stopwatch.GetTimestamp();
                    ctx.RttMs = Math.Max(0, (int)Math.Round(rttMs));
                    break;
                }
                case MessageType.ClipboardText:
                {
                    if (_clipboard.Enabled && frame.Payload.Length <= ClipboardSyncService.MaxTextBytes)
                    {
                        _clipboard.ApplyRemoteClipboard(new ClipboardPayload(false, frame.Payload));
                    }
                    break;
                }
                case MessageType.ClipboardImage:
                {
                    if (_clipboard.Enabled && frame.Payload.Length <= ClipboardSyncService.MaxImageBytes)
                    {
                        _clipboard.ApplyRemoteClipboard(new ClipboardPayload(true, frame.Payload));
                    }
                    break;
                }
                case MessageType.UpdateRequest:
                {
                    _ = Task.Run(() => StreamUpdateToClientAsync(ctx), ctx.Cts.Token);
                    break;
                }
            }
        }
    }

    private async Task StreamUpdateToClientAsync(ActiveClientContext ctx)
    {
        if (!_selfInfo.CanServeSelf || !File.Exists(_selfInfo.ExePath))
        {
            await ctx.Transport.SendAsync(
                MessageType.UpdateError,
                Encoding.UTF8.GetBytes("Host 실행 파일을 전송할 수 없는 상태입니다."),
                ctx.Cts.Token).ConfigureAwait(false);
            return;
        }

        try
        {
            Log($"클라이언트({ctx.ClientName})로 v{_selfInfo.Version} LAN 자동 업데이트 전송 시작...");
            const int chunkSize = 256 * 1024;
            byte[] buffer = new byte[chunkSize];
            long offset = 0;

            await using FileStream fs = new(_selfInfo.ExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            long totalLen = fs.Length;

            while (offset < totalLen && !ctx.Cts.Token.IsCancellationRequested)
            {
                int read = await fs.ReadAsync(buffer, ctx.Cts.Token).ConfigureAwait(false);
                if (read <= 0) break;

                byte[] slice = read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
                await ctx.Transport.SendAsync(
                    MessageType.UpdateChunk,
                    PacketCodec.EncodeUpdateChunk(new UpdateChunkPayload(offset, totalLen, slice)),
                    ctx.Cts.Token).ConfigureAwait(false);
                offset += read;
            }

            await ctx.Transport.SendAsync(
                MessageType.UpdateComplete,
                PacketCodec.EncodeUpdateComplete(_selfInfo.Sha256),
                ctx.Cts.Token).ConfigureAwait(false);

            Log($"클라이언트({ctx.ClientName}) 업데이트 전송 완료 ({totalLen / (1024 * 1024)} MB)");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"업데이트 전송 오류: {ex.Message}");
        }
    }

    private async Task HeartbeatLoopAsync(ActiveClientContext ctx)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
        while (await timer.WaitForNextTickAsync(ctx.Cts.Token).ConfigureAwait(false))
        {
            long now = Stopwatch.GetTimestamp();
            double silentMs = (now - ctx.LastAckTicks) * 1000.0 / Stopwatch.Frequency;
            if (silentMs > 3000)
            {
                Log($"클라이언트 응답 없음 ({silentMs:F0}ms) — 안전 복구 실행");
                ctx.Cts.Cancel();
                break;
            }

            await ctx.Transport.SendAsync(
                MessageType.Heartbeat,
                PacketCodec.EncodeHeartbeat(now),
                ctx.Cts.Token).ConfigureAwait(false);
            PublishStatus();
        }
    }

    private async Task UdpReceiveLoopAsync(CancellationToken ct)
    {
        if (_udpSocket is null) return;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                UdpReceiveResult res = await _udpSocket.ReceiveAsync(ct).ConfigureAwait(false);
                if (_allowPrivateNetworksOnly && !NetworkHelper.IsPrivateOrLoopback(res.RemoteEndPoint.Address))
                {
                    continue;
                }

                ActiveClientContext? ctx;
                lock (_sessionGate) { ctx = _activeClient; }
                if (ctx is null) continue;

                if (ctx.UdpCrypto.TryDecryptClientHello(res.Buffer, out _, out _))
                {
                    bool firstTime = ctx.UdpEndpoint is null;
                    ctx.UdpEndpoint = res.RemoteEndPoint;
                    ctx.LastUdpHelloTicks = Stopwatch.GetTimestamp();
                    if (firstTime)
                    {
                        Log($"UDP 모션 채널 활성화 ({res.RemoteEndPoint})");
                        PublishStatus();
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task MotionSendLoopAsync(CancellationToken ct)
    {
        byte[] packetBuf = new byte[UdpMotionCrypto.MotionPacketSize];
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(6));

        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            if (!_inputEngine.IsRemote) continue;
            if (!_coalescer.TryDrain(out int dx, out int dy)) continue;

            ActiveClientContext? ctx;
            lock (_sessionGate) { ctx = _activeClient; }
            if (ctx is null) continue;

            IPEndPoint? udpEp = ctx.UdpEndpoint;
            bool udpFresh = udpEp is not null &&
                            (Stopwatch.GetTimestamp() - ctx.LastUdpHelloTicks) * 1000.0 / Stopwatch.Frequency < 7500;

            try
            {
                if (udpFresh && udpEp is not null && _udpSocket is not null)
                {
                    int len = ctx.UdpCrypto.EncryptMotionDelta(dx, dy, 0, packetBuf);
                    await _udpSocket.SendAsync(packetBuf.AsMemory(0, len), udpEp, ct).ConfigureAwait(false);
                }
                else
                {
                    if (udpEp is not null && !udpFresh)
                    {
                        ctx.UdpEndpoint = null;
                        PublishStatus();
                    }
                    await ctx.Transport.SendAsync(
                        MessageType.UdpMotionFallback,
                        PacketCodec.EncodeUdpFallbackMotion(dx, dy),
                        ct).ConfigureAwait(false);
                }
            }
            catch
            {
                // Handled by receive/heartbeat failure
            }
        }
    }

    private async Task ControlEventPumpLoopAsync(CancellationToken ct)
    {
        await foreach (CapturedInputEvent ev in _inputEngine.Events.ReadAllAsync(ct).ConfigureAwait(false))
        {
            ActiveClientContext? ctx;
            lock (_sessionGate) { ctx = _activeClient; }
            if (ctx is null) continue;

            try
            {
                switch (ev)
                {
                    case CapturedSwitchToClientEvent sw:
                        await ctx.Transport.SendAsync(
                            MessageType.SwitchScreen,
                            PacketCodec.EncodeSwitchScreen(new SwitchScreenPayload(true, sw.HostEdge, sw.Ratio)),
                            ct).ConfigureAwait(false);
                        break;

                    case CapturedMouseButtonEvent mb:
                        await ctx.Transport.SendAsync(
                            MessageType.MouseButton,
                            PacketCodec.EncodeMouseButton(new MouseButtonPayload(mb.Button, mb.IsDown)),
                            ct).ConfigureAwait(false);
                        break;

                    case CapturedMouseWheelEvent mw:
                        await ctx.Transport.SendAsync(
                            MessageType.MouseWheel,
                            PacketCodec.EncodeMouseWheel(new MouseWheelPayload(mw.Delta, mw.IsHorizontal)),
                            ct).ConfigureAwait(false);
                        break;

                    case CapturedKeyEvent ke:
                        await ctx.Transport.SendAsync(
                            MessageType.KeyEvent,
                            PacketCodec.EncodeKeyEvent(new KeyEventPayload(ke.VirtualKey, ke.ScanCode, ke.IsExtended, ke.IsKeyUp)),
                            ct).ConfigureAwait(false);
                        break;
                }
            }
            catch
            {
                // Session cleanup handled elsewhere
            }
        }
    }

    private async Task OnLocalClipboardChangedAsync(ClipboardPayload payload)
    {
        ActiveClientContext? ctx;
        lock (_sessionGate) { ctx = _activeClient; }
        if (ctx is null) return;

        try
        {
            await ctx.Transport.SendAsync(
                payload.IsImage ? MessageType.ClipboardImage : MessageType.ClipboardText,
                payload.Data,
                ctx.Cts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Ignore transient send failures
        }
    }

    private async Task SendReleaseAllAsync()
    {
        ActiveClientContext? ctx;
        lock (_sessionGate) { ctx = _activeClient; }
        if (ctx is null) return;

        try
        {
            await ctx.Transport.SendAsync(MessageType.ReleaseAllKeys).ConfigureAwait(false);
        }
        catch
        {
            // Ignore
        }
    }

    private void PublishStatus(string? overrideMessage = null)
    {
        ActiveClientContext? ctx;
        lock (_sessionGate) { ctx = _activeClient; }

        bool connected = ctx is not null;
        bool udpActive = ctx?.UdpEndpoint is not null;
        int pairedCount = GetTrustedCount();
        bool pairingOpen = IsPinPairingOpen;

        string msg = overrideMessage ?? (connected
            ? (_inputEngine.IsRemote ? $"원격 제어 중 → {ctx!.ClientName}" : $"{ctx!.ClientName} 연결됨 (로컬 대기)")
            : (pairingOpen ? "새 기기 PIN 페어링 대기 중" : $"등록 기기 {pairedCount}대 연결 대기 중"));

        StatusChanged?.Invoke(new HostStatusSnapshot(
            IsListening: _tcpListener is not null,
            IsClientConnected: connected,
            IsRemoteControlling: _inputEngine.IsRemote,
            IsUdpActive: udpActive,
            IsPinPairingOpen: pairingOpen,
            PairedDeviceCount: pairedCount,
            ClientName: ctx?.ClientName ?? "-",
            ClientEndpoint: ctx?.RemoteEndpoint ?? "-",
            RttMs: ctx?.RttMs ?? 0,
            Pin: _pin,
            CertFingerprintShort: CertFingerprintShort,
            StatusMessage: msg));
    }

    private void Log(string msg) => LogMessage?.Invoke($"[{DateTime.Now:HH:mm:ss}] {msg}");

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();

        ActiveClientContext? ctx;
        lock (_sessionGate)
        {
            ctx = _activeClient;
            _activeClient = null;
        }
        ctx?.Dispose();

        try { _tcpListener?.Stop(); } catch { }
        _udpSocket?.Dispose();
        _clipboard.Dispose();
        _inputEngine.Dispose();
        _certificate.Dispose();
        _unauthLimiter.Dispose();
        _cts.Dispose();
    }

    private sealed class ActiveClientContext : IDisposable
    {
        public ActiveClientContext(
            ulong sessionId,
            string clientName,
            string remoteEndpoint,
            TcpClient tcp,
            SslStream ssl,
            FramedControlTransport transport,
            UdpMotionCrypto udpCrypto,
            CancellationTokenSource cts)
        {
            SessionId = sessionId;
            ClientName = clientName;
            RemoteEndpoint = remoteEndpoint;
            Tcp = tcp;
            Ssl = ssl;
            Transport = transport;
            UdpCrypto = udpCrypto;
            Cts = cts;
            LastAckTicks = Stopwatch.GetTimestamp();
        }

        public ulong SessionId { get; }
        public string ClientName { get; }
        public string RemoteEndpoint { get; }
        public TcpClient Tcp { get; }
        public SslStream Ssl { get; }
        public FramedControlTransport Transport { get; }
        public UdpMotionCrypto UdpCrypto { get; }
        public CancellationTokenSource Cts { get; }
        public long LastAckTicks;
        public int RttMs;
        public IPEndPoint? UdpEndpoint;
        public long LastUdpHelloTicks;

        public void Dispose()
        {
            try { Cts.Cancel(); } catch { }
            Transport.Dispose();
            UdpCrypto.Dispose();
            try { Ssl.Dispose(); } catch { }
            try { Tcp.Dispose(); } catch { }
            Cts.Dispose();
        }
    }
}
