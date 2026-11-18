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
using LanKvm.Core.Native;
using LanKvm.Core.Update;
using LanKvm.Protocol;

namespace LanKvm.Core.Network;

public sealed record ClientStatusSnapshot(
    bool IsConnecting,
    bool IsConnected,
    bool IsControlledByHost,
    bool IsUdpActive,
    bool IsPaired,
    string HostName,
    string ServerFingerprintShort,
    string StatusMessage);

/// <summary>
/// Connects outbound from Laptop (Client) to Desktop (Host) via TCP+TLS,
/// authenticates automatically via DPAPI-protected DeviceToken (or 1-time PIN),
/// maintains NAT UDP mapping with UDP_HELLO packets, injects received input,
/// and optionally syncs newer LanKvm.exe updates from the authenticated Host.
/// </summary>
public sealed class KvmClientSession : IDisposable
{
    private readonly string _hostIp;
    private readonly int _tcpPort;
    private readonly int _udpPort;
    private readonly string _pin;
    private readonly string? _expectedFingerprint;
    private readonly ClientInputInjector _injector;
    private readonly ClipboardSyncService _clipboard;
    private readonly CancellationTokenSource _cts = new();
    private readonly bool _autoReconnect;
    private readonly bool _autoSyncUpdateFromHost;

    private string? _savedClientId;
    private byte[]? _savedRawToken;

    private FramedControlTransport? _transport;
    private FileStream? _updateStream;
    private string? _updateStagingPath;
    private string? _expectedUpdateSha256;
    private bool _keepUpdateStagingFile;
    private bool _disposed;
    private string _hostName = "-";
    private string _serverFingerprintHex = string.Empty;
    private bool _isConnected;
    private bool _isUdpActive;

    public event Action<ClientStatusSnapshot>? StatusChanged;
    public event Action<string, string>? TrustedFingerprintObserved;
    public event Action<string, PairedServerRecord>? PairingCredentialIssued;
    public event Action<string>? PairingInvalidated;
    public event Action<string>? UpdateReadyToApply;
    public event Action<string>? LogMessage;

    public KvmClientSession(
        string hostIp,
        int tcpPort,
        int udpPort,
        string pin,
        string? expectedFingerprint,
        PairedServerRecord? pairedServer,
        double sensitivity,
        int returnResistancePx,
        bool clipboardEnabled,
        bool autoReconnect = true,
        bool autoSyncUpdateFromHost = true)
    {
        _hostIp = hostIp.Trim();
        _tcpPort = tcpPort;
        _udpPort = udpPort;
        _pin = pin.Trim();
        _expectedFingerprint = pairedServer?.ServerFingerprintHex ?? expectedFingerprint;
        _autoReconnect = autoReconnect;
        _autoSyncUpdateFromHost = autoSyncUpdateFromHost;

        if (pairedServer is not null)
        {
            byte[]? raw = DpapiHelper.TryUnprotectFromBase64(pairedServer.EncryptedTokenBase64);
            if (raw is { Length: > 0 } && !string.IsNullOrEmpty(pairedServer.ClientId))
            {
                _savedClientId = pairedServer.ClientId;
                _savedRawToken = raw;
            }
        }

        _injector = new ClientInputInjector(returnResistancePx)
        {
            Sensitivity = sensitivity
        };
        _injector.ReturnToHostRequested += (hostEdge, ratio) =>
        {
            _ = SendEdgeReturnAsync(hostEdge, ratio);
            PublishStatus("데스크탑으로 제어권 복귀");
        };

        _clipboard = new ClipboardSyncService(OnLocalClipboardChangedAsync)
        {
            Enabled = clipboardEnabled
        };
    }

    public double Sensitivity
    {
        get => _injector.Sensitivity;
        set => _injector.Sensitivity = value;
    }

    public bool ClipboardEnabled
    {
        get => _clipboard.Enabled;
        set => _clipboard.Enabled = value;
    }

    public void Start()
    {
        _clipboard.Start();
        _ = Task.Run(() => RunWithReconnectAsync(_cts.Token));
    }

    private async Task RunWithReconnectAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            bool shouldRetry = await RunSingleSessionAsync(ct).ConfigureAwait(false);
            if (!shouldRetry || !_autoReconnect || ct.IsCancellationRequested)
            {
                break;
            }

            PublishStatus("2.5초 후 재연결 시도...", connecting: true);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2.5), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        PublishStatus("연결 종료됨");
    }

    private async Task<bool> RunSingleSessionAsync(CancellationToken ct)
    {
        bool hasToken = !string.IsNullOrEmpty(_savedClientId) && _savedRawToken is { Length: > 0 };
        if (!hasToken && (_pin.Length != 6 || !_pin.All(char.IsDigit)))
        {
            Log("최초 1회 페어링을 위해 6자리 PIN 입력이 필요합니다.");
            PublishStatus("최초 1회 6자리 PIN 입력 필요");
            return false;
        }

        using var tcp = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        NetworkHelper.DisableUdpConnReset(udp.Client);
        bool fingerprintMismatch = false;

        try
        {
            PublishStatus($"{_hostIp}:{_tcpPort} 연결 시도 중...", connecting: true);
            Log($"Host 연결 시도: {_hostIp}:{_tcpPort} ({(hasToken ? "등록 기기 자동 인증" : "최초 PIN 페어링")})");

            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectCts.CancelAfter(TimeSpan.FromSeconds(6));
                await tcp.ConnectAsync(_hostIp, _tcpPort, connectCts.Token).ConfigureAwait(false);
            }

            string? observedFingerprint = null;
            using var ssl = new SslStream(
                tcp.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, cert, _, _) =>
                {
                    if (cert is null) return false;
                    observedFingerprint = TlsPairing.GetCertificateFingerprint(cert);
                    if (!string.IsNullOrEmpty(_expectedFingerprint) &&
                        !string.Equals(_expectedFingerprint, observedFingerprint, StringComparison.OrdinalIgnoreCase))
                    {
                        fingerprintMismatch = true;
                        return false;
                    }
                    return true;
                });

            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = _hostIp,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                },
                ct).ConfigureAwait(false);

            _serverFingerprintHex = observedFingerprint ?? string.Empty;
            using var transport = new FramedControlTransport(ssl);
            _transport = transport;

            ControlFrame? challengeFrame = await transport.ReceiveAsync(ct).ConfigureAwait(false);
            if (challengeFrame is null || challengeFrame.Type != MessageType.PinChallenge)
            {
                throw new InvalidDataException("서버로부터 인증 챌린지를 받지 못했습니다.");
            }

            PinChallengePayload challenge = PacketCodec.DecodePinChallenge(challengeFrame.Payload);
            byte[] clientNonce = RandomNumberGenerator.GetBytes(32);
            var primary = Screen.PrimaryScreen?.Bounds ?? new System.Drawing.Rectangle(0, 0, 1920, 1080);

            PinResponsePayload authReq = hasToken
                ? new PinResponsePayload(
                    AuthMode.DeviceToken,
                    _savedClientId!,
                    clientNonce,
                    _savedRawToken!,
                    Environment.MachineName,
                    primary.Width,
                    primary.Height)
                : new PinResponsePayload(
                    AuthMode.PinPairing,
                    string.Empty,
                    clientNonce,
                    TlsPairing.ComputePinHmac(_pin, challenge.ServerNonce, clientNonce, _serverFingerprintHex),
                    Environment.MachineName,
                    primary.Width,
                    primary.Height);

            await transport.SendAsync(
                MessageType.PinResponse,
                PacketCodec.EncodePinResponse(authReq),
                ct).ConfigureAwait(false);

            ControlFrame? authFrame = await transport.ReceiveAsync(ct).ConfigureAwait(false);
            if (authFrame is null || authFrame.Type != MessageType.AuthResult)
            {
                throw new InvalidDataException("인증 응답을 받지 못했습니다.");
            }

            AuthResultPayload auth = PacketCodec.DecodeAuthResult(authFrame.Payload);
            if (!auth.Accepted)
            {
                Log($"인증 거절: {auth.Reason}");
                PublishStatus($"인증 실패: {auth.Reason}");

                if (hasToken && auth.Reason.Contains("DEVICE_TOKEN_INVALID", StringComparison.Ordinal))
                {
                    _savedClientId = null;
                    _savedRawToken = null;
                    PairingInvalidated?.Invoke($"{_hostIp}:{_tcpPort}");
                }
                return false;
            }

            string endpointKey = $"{_hostIp}:{_tcpPort}";
            if (!string.IsNullOrEmpty(auth.IssuedClientId) && auth.IssuedToken is { Length: > 0 })
            {
                _savedClientId = auth.IssuedClientId;
                _savedRawToken = auth.IssuedToken;
                string enc = DpapiHelper.ProtectToBase64(auth.IssuedToken);
                PairingCredentialIssued?.Invoke(endpointKey, new PairedServerRecord(auth.IssuedClientId, enc, _serverFingerprintHex));
                Log("영구 기기 페어링 완료 — 다음부터는 PIN 없이 자동 연결됩니다.");
            }
            else
            {
                TrustedFingerprintObserved?.Invoke(endpointKey, _serverFingerprintHex);
            }

            _hostName = auth.HostName;
            _isConnected = true;

            Log($"연결 성공! Host={auth.HostName} (v{auth.AppVersion}), 지문={TlsPairing.FormatFingerprintShort(_serverFingerprintHex)}");
            PublishStatus($"{auth.HostName}에 연결됨 (제어 대기)");

            if (_autoSyncUpdateFromHost &&
                !string.IsNullOrWhiteSpace(auth.AppVersion) &&
                !string.IsNullOrWhiteSpace(auth.ExeSha256))
            {
                var selfInfo = AppUpdater.GetSelfExecutableInfo();
                if (selfInfo.CanServeSelf && AppUpdater.IsNewerVersion(auth.AppVersion, selfInfo.Version))
                {
                    _expectedUpdateSha256 = auth.ExeSha256;
                    Log($"Host가 더 최신 버전(v{auth.AppVersion} > v{selfInfo.Version})입니다. LAN 자동 업데이트를 요청합니다...");
                    await transport.SendAsync(MessageType.UpdateRequest, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
                }
            }

            using var udpCrypto = new UdpMotionCrypto(auth.SessionId, auth.UdpSessionKey);
            IPAddress remoteIp = ((IPEndPoint)tcp.Client.RemoteEndPoint!).Address;
            var udpHostEp = new IPEndPoint(remoteIp, _udpPort);

            using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var udpHelloTask = Task.Run(() => UdpHelloLoopAsync(udp, udpHostEp, udpCrypto, sessionCts.Token), sessionCts.Token);
            var udpRecvTask = Task.Run(() => UdpReceiveLoopAsync(udp, udpCrypto, sessionCts.Token), sessionCts.Token);
            try
            {
                await TcpReceiveLoopAsync(transport, sessionCts.Token).ConfigureAwait(false);
            }
            finally
            {
                sessionCts.Cancel();
                try { await Task.WhenAll(udpHelloTask, udpRecvTask).ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                catch (ObjectDisposedException) { }
            }

            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            if (fingerprintMismatch)
            {
                Log("서버 인증서 지문이 저장된 신뢰 목록과 다릅니다. 신뢰 인증서를 초기화하고 재시도하세요.");
                PublishStatus("인증서 지문 불일치");
                return false;
            }

            Log($"연결 오류: {ex.Message}");
            PublishStatus($"연결 끊김: {ex.Message}");
            return true;
        }
        finally
        {
            CleanupPendingUpdateStream();
            _isConnected = false;
            _isUdpActive = false;
            _transport = null;
            _injector.DeactivateAndReleaseAll();
        }
    }

    private async Task UdpHelloLoopAsync(
        UdpClient udp,
        IPEndPoint hostEp,
        UdpMotionCrypto crypto,
        CancellationToken ct)
    {
        byte[] packet = new byte[UdpMotionCrypto.HelloPacketSize];

        for (int i = 0; i < 3 && !ct.IsCancellationRequested; i++)
        {
            int len = crypto.EncryptClientHello(Stopwatch.GetTimestamp(), packet);
            await udp.SendAsync(packet.AsMemory(0, len), hostEp, ct).ConfigureAwait(false);
            await Task.Delay(200, ct).ConfigureAwait(false);
        }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2.5));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            int len = crypto.EncryptClientHello(Stopwatch.GetTimestamp(), packet);
            await udp.SendAsync(packet.AsMemory(0, len), hostEp, ct).ConfigureAwait(false);
        }
    }

    private async Task UdpReceiveLoopAsync(
        UdpClient udp,
        UdpMotionCrypto crypto,
        CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult res = await udp.ReceiveAsync(ct).ConfigureAwait(false);
            if (crypto.TryDecryptMotionDelta(res.Buffer, out _, out _, out int dx, out int dy, out _))
            {
                if (!_isUdpActive)
                {
                    _isUdpActive = true;
                    Log("UDP 저지연 모션 수신 시작");
                    PublishStatus();
                }
                _injector.InjectMouseDelta(dx, dy);
            }
        }
    }

    private async Task TcpReceiveLoopAsync(FramedControlTransport transport, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            ControlFrame? frame = await transport.ReceiveAsync(ct).ConfigureAwait(false);
            if (frame is null) break;

            switch (frame.Type)
            {
                case MessageType.SwitchScreen:
                {
                    var sw = PacketCodec.DecodeSwitchScreen(frame.Payload);
                    if (sw.ToClient)
                    {
                        _injector.ActivateFromHost(sw.EntryEdge, sw.Ratio);
                        PublishStatus($"{_hostName}에서 마우스/키보드 제어 중");
                    }
                    else
                    {
                        _injector.DeactivateAndReleaseAll();
                        PublishStatus($"{_hostName}에 연결됨 (대기)");
                    }
                    break;
                }
                case MessageType.UdpMotionFallback:
                {
                    var motion = PacketCodec.DecodeUdpFallbackMotion(frame.Payload);
                    _injector.InjectMouseDelta(motion.Dx, motion.Dy);
                    break;
                }
                case MessageType.MouseButton:
                    _injector.InjectMouseButton(PacketCodec.DecodeMouseButton(frame.Payload));
                    break;

                case MessageType.MouseWheel:
                    _injector.InjectMouseWheel(PacketCodec.DecodeMouseWheel(frame.Payload));
                    break;

                case MessageType.KeyEvent:
                    _injector.InjectKeyEvent(PacketCodec.DecodeKeyEvent(frame.Payload));
                    break;

                case MessageType.ReleaseAllKeys:
                    _injector.DeactivateAndReleaseAll();
                    PublishStatus($"{_hostName}에 연결됨 (대기)");
                    break;

                case MessageType.ClipboardText:
                    if (_clipboard.Enabled && frame.Payload.Length <= ClipboardSyncService.MaxTextBytes)
                    {
                        _clipboard.ApplyRemoteClipboard(new ClipboardPayload(false, frame.Payload));
                    }
                    break;

                case MessageType.ClipboardImage:
                    if (_clipboard.Enabled && frame.Payload.Length <= ClipboardSyncService.MaxImageBytes)
                    {
                        _clipboard.ApplyRemoteClipboard(new ClipboardPayload(true, frame.Payload));
                    }
                    break;

                case MessageType.Heartbeat:
                    await transport.SendAsync(MessageType.HeartbeatAck, frame.Payload, ct).ConfigureAwait(false);
                    break;

                case MessageType.UpdateChunk:
                {
                    const long maxUpdateBytes = 512L * 1024 * 1024;
                    var chunk = PacketCodec.DecodeUpdateChunk(frame.Payload);
                    if (chunk.TotalLength <= 0 || chunk.TotalLength > maxUpdateBytes)
                    {
                        CleanupPendingUpdateStream();
                        break;
                    }
                    if (_updateStream is null)
                    {
                        _updateStagingPath = AppUpdater.GetStagingUpdatePath();
                        _updateStream = new FileStream(_updateStagingPath, FileMode.Create, FileAccess.Write, FileShare.None);
                    }
                    if (chunk.Offset == _updateStream.Position &&
                        _updateStream.Position + chunk.Data.Length <= chunk.TotalLength)
                    {
                        await _updateStream.WriteAsync(chunk.Data, ct).ConfigureAwait(false);
                    }
                    break;
                }

                case MessageType.UpdateComplete:
                {
                    var done = PacketCodec.DecodeUpdateComplete(frame.Payload);
                    string? path = _updateStagingPath;
                    if (_updateStream is not null)
                    {
                        await _updateStream.FlushAsync(ct).ConfigureAwait(false);
                        await _updateStream.DisposeAsync().ConfigureAwait(false);
                        _updateStream = null;
                    }

                    if (!string.IsNullOrEmpty(path) && File.Exists(path))
                    {
                        string actualSha = AppUpdater.ComputeFileSha256Hex(path);
                        bool matchesAuthSha = string.IsNullOrEmpty(_expectedUpdateSha256) ||
                                              string.Equals(actualSha, _expectedUpdateSha256, StringComparison.OrdinalIgnoreCase);
                        if (matchesAuthSha && string.Equals(actualSha, done.Sha256Hex, StringComparison.OrdinalIgnoreCase))
                        {
                            _keepUpdateStagingFile = true;
                            Log("LAN 업데이트 파일 검증 완료! 새 버전으로 재시작합니다...");
                            UpdateReadyToApply?.Invoke(path);
                            return;
                        }
                        else
                        {
                            Log("LAN 업데이트 SHA-256 검증 실패로 취소되었습니다.");
                            CleanupPendingUpdateStream();
                        }
                    }
                    break;
                }

                case MessageType.UpdateError:
                {
                    string err = Encoding.UTF8.GetString(frame.Payload);
                    Log($"업데이트 수신 불가: {err}");
                    CleanupPendingUpdateStream();
                    break;
                }
            }
        }
    }

    private void CleanupPendingUpdateStream()
    {
        try
        {
            _updateStream?.Dispose();
            _updateStream = null;
            if (!_keepUpdateStagingFile &&
                !string.IsNullOrEmpty(_updateStagingPath) &&
                File.Exists(_updateStagingPath))
            {
                File.Delete(_updateStagingPath);
            }
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    private async Task SendEdgeReturnAsync(ScreenEdge hostEdge, float ratio)
    {
        FramedControlTransport? t = _transport;
        if (t is null || _cts.IsCancellationRequested) return;

        try
        {
            await t.SendAsync(
                MessageType.EdgeReturn,
                PacketCodec.EncodeEdgeReturn(new EdgeReturnPayload(hostEdge, ratio)),
                _cts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Ignore transient shutdown send errors
        }
    }

    private async Task OnLocalClipboardChangedAsync(ClipboardPayload payload)
    {
        FramedControlTransport? t = _transport;
        if (t is null || _cts.IsCancellationRequested) return;

        try
        {
            await t.SendAsync(
                payload.IsImage ? MessageType.ClipboardImage : MessageType.ClipboardText,
                payload.Data,
                _cts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Ignore
        }
    }

    private void PublishStatus(string? message = null, bool connecting = false)
    {
        string msg = message ?? (_isConnected
            ? (_injector.IsControlledByHost ? $"{_hostName}에서 제어 중" : $"{_hostName}에 연결됨 (대기)")
            : "연결 안 됨");

        bool isPaired = !string.IsNullOrEmpty(_savedClientId) && _savedRawToken is { Length: > 0 };

        StatusChanged?.Invoke(new ClientStatusSnapshot(
            IsConnecting: connecting,
            IsConnected: _isConnected,
            IsControlledByHost: _injector.IsControlledByHost,
            IsUdpActive: _isUdpActive,
            IsPaired: isPaired,
            HostName: _hostName,
            ServerFingerprintShort: TlsPairing.FormatFingerprintShort(_serverFingerprintHex),
            StatusMessage: msg));
    }

    private void Log(string msg) => LogMessage?.Invoke($"[{DateTime.Now:HH:mm:ss}] {msg}");

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        CleanupPendingUpdateStream();
        _clipboard.Dispose();
        _injector.DeactivateAndReleaseAll();
        _cts.Dispose();
    }
}
