using System.ComponentModel;
using System.Drawing;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using LanKvm.Core;
using LanKvm.Core.Native;
using LanKvm.Core.Network;
using LanKvm.Core.Update;
using LanKvm.Protocol;
using WinForms = System.Windows.Forms;

namespace LanKvm.App;

public partial class MainWindow : Window
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private enum TrayDotState { Idle, Connecting, Connected, Remote }

    private static readonly SolidColorBrush BrushSlate = CreateFrozenBrush(71, 85, 105);
    private static readonly SolidColorBrush BrushIdle = CreateFrozenBrush(51, 65, 85);
    private static readonly SolidColorBrush BrushAmber = CreateFrozenBrush(217, 119, 6);
    private static readonly SolidColorBrush BrushGreen = CreateFrozenBrush(22, 163, 74);
    private static readonly SolidColorBrush BrushBlue = CreateFrozenBrush(2, 132, 199);
    private static readonly SolidColorBrush BrushTextBlue = CreateFrozenBrush(56, 189, 248);
    private static readonly SolidColorBrush BrushTextGreen = CreateFrozenBrush(74, 222, 128);
    private static readonly SolidColorBrush BrushTextAmber = CreateFrozenBrush(251, 191, 36);
    private static readonly SolidColorBrush BrushAdminOk = CreateFrozenBrush(20, 83, 45);
    private static readonly SolidColorBrush BrushAdminNormal = CreateFrozenBrush(30, 58, 95);

    private readonly AppConfig _config;
    private readonly List<string> _logLines = new(80);
    private readonly Dictionary<TrayDotState, System.Drawing.Icon> _trayIcons;
    private readonly WinForms.NotifyIcon _trayIcon;

    private KvmHostSession? _hostSession;
    private KvmClientSession? _clientSession;
    private HostStatusSnapshot? _lastHostSnap;
    private ClientStatusSnapshot? _lastClientSnap;
    private TrayDotState? _currentTrayState;
    private string _lastTrayTooltip = string.Empty;
    private bool _logDirty;
    private bool _allowExit;
    private bool _initialized;

    public MainWindow(bool startMinimized = false)
    {
        InitializeComponent();

        _config = ConfigStore.Load();
        AppTitleText.Text = $"LanKvm v{AppUpdater.GetCurrentVersionString()}";

        _trayIcons = new Dictionary<TrayDotState, System.Drawing.Icon>
        {
            [TrayDotState.Idle] = BuildTrayIcon(System.Drawing.Color.SlateGray),
            [TrayDotState.Connecting] = BuildTrayIcon(System.Drawing.Color.Gold),
            [TrayDotState.Connected] = BuildTrayIcon(System.Drawing.Color.LimeGreen),
            [TrayDotState.Remote] = BuildTrayIcon(System.Drawing.Color.DeepSkyBlue)
        };
        _trayIcon = CreateTrayIcon();
        SetTrayState(TrayDotState.Idle);
        _trayIcon.Visible = true;

        ApplyLoadedConfig();
        RefreshEnvironmentInfo();
        _initialized = true;

        if (startMinimized)
        {
            Hide();
        }

        if (_config.AutoStartService)
        {
            if (_config.Role == AppRole.Host)
            {
                StartHostCore();
            }
            else if (IsCurrentClientEndpointPaired())
            {
                StartClientCore();
            }
        }

        if (_config.CheckGitHubUpdatesOnStart && !string.IsNullOrWhiteSpace(_config.GitHubRepo))
        {
            _ = CheckGitHubUpdateAsync(silentIfUpToDate: true);
        }

        if (startMinimized)
        {
            NetworkHelper.TrimBackgroundMemory();
        }
    }

    private static SolidColorBrush CreateFrozenBrush(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private static System.Drawing.Icon BuildTrayIcon(System.Drawing.Color dotColor)
    {
        using var bmp = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(System.Drawing.Color.Transparent);
            using var bgBrush = new SolidBrush(System.Drawing.Color.FromArgb(30, 41, 59));
            using var dotBrush = new SolidBrush(dotColor);
            g.FillEllipse(bgBrush, 0, 0, 15, 15);
            g.FillEllipse(dotBrush, 3, 3, 10, 10);
        }

        IntPtr hIcon = bmp.GetHicon();
        try
        {
            using var temp = System.Drawing.Icon.FromHandle(hIcon);
            return (System.Drawing.Icon)temp.Clone();
        }
        finally
        {
            DestroyIcon(hIcon);
        }
    }

    private WinForms.NotifyIcon CreateTrayIcon()
    {
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("창 열기", null, (_, _) => Dispatcher.Invoke(RestoreFromTray));
        menu.Items.Add("로컬 제어 복구", null, (_, _) => Dispatcher.Invoke(() => _hostSession?.ForceReturnToLocal()));
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("종료", null, (_, _) => Dispatcher.Invoke(ExitApplication));

        var notify = new WinForms.NotifyIcon
        {
            Text = "LanKvm — 대기 중",
            Visible = false,
            ContextMenuStrip = menu
        };
        notify.DoubleClick += (_, _) => Dispatcher.Invoke(RestoreFromTray);
        return notify;
    }

    private void SetTrayState(TrayDotState state)
    {
        if (_currentTrayState == state) return;
        _currentTrayState = state;
        _trayIcon.Icon = _trayIcons[state];
    }

    private void ApplyLoadedConfig()
    {
        if (_config.Role == AppRole.Host)
            HostRoleRadio.IsChecked = true;
        else
            ClientRoleRadio.IsChecked = true;

        HostTcpPortBox.Text = _config.TcpPort.ToString();
        HostUdpPortBox.Text = _config.UdpPort.ToString();
        ResistanceBox.Text = _config.EdgeResistancePx.ToString();

        ClientHostIpBox.Text = _config.HostIp;
        ClientTcpPortBox.Text = _config.TcpPort.ToString();
        ClientUdpPortBox.Text = _config.UdpPort.ToString();
        SensitivitySlider.Value = Math.Clamp(_config.ClientSensitivity, 0.3, 2.5);
        SensitivityLabel.Text = $"{SensitivitySlider.Value:0.0}x";

        AutoStartServiceCheck.IsChecked = _config.AutoStartService;
        StartWithWindowsCheck.IsChecked = NetworkHelper.IsStartWithWindowsEnabled() || _config.StartWithWindows;
        PrivateNetOnlyCheck.IsChecked = _config.AllowPrivateNetworksOnly;
        ClipboardCheck.IsChecked = _config.ClipboardSyncEnabled;
        AutoSyncHostCheck.IsChecked = _config.AutoSyncUpdateFromHost;
        GitHubRepoBox.Text = _config.GitHubRepo;
        CheckGitHubOnStartCheck.IsChecked = _config.CheckGitHubUpdatesOnStart;

        foreach (ComboBoxItem item in EdgeCombo.Items)
        {
            if (string.Equals(item.Tag?.ToString(), _config.SwitchEdge.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                EdgeCombo.SelectedItem = item;
                break;
            }
        }

        UpdateRolePanels();
        RefreshClientPairingUi();
    }

    private void RefreshEnvironmentInfo()
    {
        IReadOnlyList<string> ips = NetworkHelper.GetLocalIPv4Addresses();
        LocalIpTextBox.Text = ips.Count > 0 ? string.Join(" , ", ips) : "감지된 IPv4 주소 없음";

        bool isAdmin = NetworkHelper.IsRunAsAdministrator();
        AdminBadgeText.Text = isAdmin ? "관리자 권한" : "일반 권한";
        AdminBadge.Background = isAdmin ? BrushAdminOk : BrushAdminNormal;
        ElevateButton.Visibility = isAdmin ? Visibility.Collapsed : Visibility.Visible;
    }

    private void RoleRadio_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        UpdateRolePanels();
        SaveCurrentConfig();

        if (ClientRoleRadio.IsChecked == true &&
            _config.AutoStartService &&
            _clientSession is null &&
            _hostSession is null &&
            IsCurrentClientEndpointPaired())
        {
            StartClientCore();
        }
    }

    private void UpdateRolePanels()
    {
        bool isHost = HostRoleRadio.IsChecked == true;
        HostPanel.Visibility = isHost ? Visibility.Visible : Visibility.Collapsed;
        ClientPanel.Visibility = isHost ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ClientEndpoint_Changed(object sender, TextChangedEventArgs e)
    {
        if (!_initialized) return;
        RefreshClientPairingUi();
        if (ClientRoleRadio.IsChecked == true &&
            _config.AutoStartService &&
            _clientSession is null &&
            _hostSession is null &&
            IsCurrentClientEndpointPaired())
        {
            StartClientCore();
        }
    }

    private bool IsCurrentClientEndpointPaired()
    {
        string key = $"{ClientHostIpBox.Text.Trim()}:{ClientTcpPortBox.Text.Trim()}";
        return _config.PairedServers.TryGetValue(key, out PairedServerRecord? rec) &&
               DpapiHelper.TryUnprotectFromBase64(rec.EncryptedTokenBase64) is { Length: > 0 };
    }

    private void RefreshClientPairingUi()
    {
        bool paired = IsCurrentClientEndpointPaired();
        if (paired)
        {
            ClientPairingStatusText.Text = "페어링 완료 — PIN 입력 없이 자동 연결됩니다";
            ClientPairingStatusText.Foreground = BrushTextGreen;
            ClientPinBox.Text = string.Empty;
            ClientPinBox.IsEnabled = false;
        }
        else
        {
            ClientPairingStatusText.Text = "최초 1회 PIN 입력 필요 (이후 자동 연결)";
            ClientPairingStatusText.Foreground = BrushTextAmber;
            ClientPinBox.IsEnabled = true;
        }
    }

    private void HostSetting_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_initialized) return;
        ScreenEdge edge = GetSelectedEdge();
        _config.SwitchEdge = edge;
        if (_hostSession is not null)
        {
            _hostSession.SwitchEdge = edge;
        }
        SaveCurrentConfig();
    }

    private void SensitivitySlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (SensitivityLabel is null) return;
        double val = Math.Round(e.NewValue, 1);
        SensitivityLabel.Text = $"{val:0.0}x";
        if (_clientSession is not null)
        {
            _clientSession.Sensitivity = val;
        }
        if (_initialized)
        {
            _config.ClientSensitivity = val;
            SaveCurrentConfig();
        }
    }

    private void ClipboardCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        bool enabled = ClipboardCheck.IsChecked == true;
        _config.ClipboardSyncEnabled = enabled;
        if (_hostSession is not null) _hostSession.ClipboardEnabled = enabled;
        if (_clientSession is not null) _clientSession.ClipboardEnabled = enabled;
        SaveCurrentConfig();
    }

    private void PrivateNetOnly_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        bool privateOnly = PrivateNetOnlyCheck.IsChecked == true;
        _config.AllowPrivateNetworksOnly = privateOnly;
        if (_hostSession is not null) _hostSession.AllowPrivateNetworksOnly = privateOnly;
        SaveCurrentConfig();
    }

    private void OptionCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        SaveCurrentConfig();
    }

    private void StartWithWindows_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        bool enable = StartWithWindowsCheck.IsChecked == true;
        var (ok, message) = NetworkHelper.SetStartWithWindows(enable);
        AppendLog($"[{DateTime.Now:HH:mm:ss}] {message}");
        if (!ok)
        {
            _initialized = false;
            StartWithWindowsCheck.IsChecked = !enable;
            _initialized = true;
            System.Windows.MessageBox.Show(message, "시작 프로그램 설정", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _config.StartWithWindows = enable;
        SaveCurrentConfig();
    }

    private void HostStart_Click(object sender, RoutedEventArgs e) => StartHostCore();

    private void StartHostCore()
    {
        if (!TryParsePorts(HostTcpPortBox.Text, HostUdpPortBox.Text, out int tcpPort, out int udpPort)) return;
        if (!int.TryParse(ResistanceBox.Text, out int resistance) || resistance < 0 || resistance > 200)
        {
            ShowError("경계 저항(px)은 0~200 사이 정수를 입력하세요.");
            return;
        }

        StopAllSessions();
        SaveCurrentConfig();

        try
        {
            _hostSession = new KvmHostSession(
                tcpPort,
                udpPort,
                ConfigStore.HostCertPath,
                GetSelectedEdge(),
                resistance,
                ClipboardCheck.IsChecked == true,
                PrivateNetOnlyCheck.IsChecked == true,
                _config.TrustedClients);

            _hostSession.StatusChanged += snap => Dispatcher.Invoke(() => ApplyHostStatus(snap));
            _hostSession.LogMessage += msg => Dispatcher.Invoke(() => AppendLog(msg));
            _hostSession.TrustedClientAdded += record => Dispatcher.Invoke(() =>
            {
                _config.TrustedClients.Add(record);
                SaveCurrentConfig();
            });
            _hostSession.Start();

            HostStartButton.IsEnabled = false;
            HostStopButton.IsEnabled = true;
            ForceLocalButton.IsEnabled = true;
            OpenPairingButton.IsEnabled = true;
            HostRoleRadio.IsEnabled = false;
            ClientRoleRadio.IsEnabled = false;

            HostFingerprintText.Text = $"지문: {_hostSession.CertFingerprintShort}";
        }
        catch (Exception ex)
        {
            ShowError($"Host 시작 실패: {ex.Message}");
            StopAllSessions();
        }
    }

    private void HostStop_Click(object sender, RoutedEventArgs e) => StopAllSessions();

    private void ForceLocal_Click(object sender, RoutedEventArgs e) => _hostSession?.ForceReturnToLocal();

    private void OpenPairing_Click(object sender, RoutedEventArgs e)
    {
        _hostSession?.OpenPairingWindow(TimeSpan.FromMinutes(3));
    }

    private void ClearPairedClients_Click(object sender, RoutedEventArgs e)
    {
        _config.TrustedClients.Clear();
        SaveCurrentConfig();
        _hostSession?.ClearTrustedClients();
        AppendLog($"[{DateTime.Now:HH:mm:ss}] 등록된 노트북 목록을 초기화했습니다.");
    }

    private void ClientConnect_Click(object sender, RoutedEventArgs e) => StartClientCore();

    private void StartClientCore()
    {
        string hostIp = ClientHostIpBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(hostIp))
        {
            ShowError("데스크탑(Host) IP 주소를 입력하세요.");
            return;
        }
        if (!TryParsePorts(ClientTcpPortBox.Text, ClientUdpPortBox.Text, out int tcpPort, out int udpPort)) return;

        string key = $"{hostIp}:{tcpPort}";
        _config.PairedServers.TryGetValue(key, out PairedServerRecord? pairedServer);
        bool hasValidToken = pairedServer is not null &&
                             DpapiHelper.TryUnprotectFromBase64(pairedServer.EncryptedTokenBase64) is { Length: > 0 };

        string pin = ClientPinBox.Text.Trim();
        if (!hasValidToken && (pin.Length != 6 || !pin.All(char.IsDigit)))
        {
            ShowError("최초 1회 연결을 위해 Host 화면에 표시된 6자리 숫자 PIN을 입력하세요.");
            return;
        }

        StopAllSessions();
        SaveCurrentConfig();

        _config.TrustedServerFingerprints.TryGetValue(key, out string? expectedFp);

        _clientSession = new KvmClientSession(
            hostIp,
            tcpPort,
            udpPort,
            pin,
            expectedFp,
            hasValidToken ? pairedServer : null,
            SensitivitySlider.Value,
            returnResistancePx: 16,
            clipboardEnabled: ClipboardCheck.IsChecked == true,
            autoReconnect: _config.AutoReconnect,
            autoSyncUpdateFromHost: AutoSyncHostCheck.IsChecked == true);

        _clientSession.StatusChanged += snap => Dispatcher.Invoke(() => ApplyClientStatus(snap));
        _clientSession.LogMessage += msg => Dispatcher.Invoke(() => AppendLog(msg));
        _clientSession.TrustedFingerprintObserved += (endpointKey, fp) =>
        {
            Dispatcher.Invoke(() =>
            {
                _config.TrustedServerFingerprints[endpointKey] = fp;
                SaveCurrentConfig();
            });
        };
        _clientSession.PairingCredentialIssued += (endpointKey, rec) =>
        {
            Dispatcher.Invoke(() =>
            {
                _config.PairedServers[endpointKey] = rec;
                _config.TrustedServerFingerprints[endpointKey] = rec.ServerFingerprintHex;
                SaveCurrentConfig();
                RefreshClientPairingUi();
            });
        };
        _clientSession.PairingInvalidated += endpointKey =>
        {
            Dispatcher.Invoke(() =>
            {
                _config.PairedServers.Remove(endpointKey);
                SaveCurrentConfig();
                RefreshClientPairingUi();
            });
        };
        _clientSession.UpdateReadyToApply += stagedPath =>
        {
            Dispatcher.Invoke(() => ApplyStagedUpdateAndRestart(stagedPath));
        };

        _clientSession.Start();

        ClientConnectButton.IsEnabled = false;
        ClientDisconnectButton.IsEnabled = true;
        HostRoleRadio.IsEnabled = false;
        ClientRoleRadio.IsEnabled = false;
    }

    private void ClientDisconnect_Click(object sender, RoutedEventArgs e) => StopAllSessions();

    private async void DiagnoseConnection_Click(object sender, RoutedEventArgs e)
    {
        string ip = ClientHostIpBox.Text.Trim();
        if (!int.TryParse(ClientTcpPortBox.Text, out int port))
        {
            ShowError("유효한 TCP 포트를 입력하세요.");
            return;
        }

        DiagnoseButton.IsEnabled = false;
        AppendLog($"[{DateTime.Now:HH:mm:ss}] 연결 테스트 중: {ip}:{port} ...");
        try
        {
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await tcp.ConnectAsync(ip, port, cts.Token);
            AppendLog($"[{DateTime.Now:HH:mm:ss}] 성공! {ip}:{port} TCP 도달 가능합니다.");
            System.Windows.MessageBox.Show(
                $"성공! {ip}:{port} 포트로 연결할 수 있습니다.",
                "연결 테스트 성공",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendLog($"[{DateTime.Now:HH:mm:ss}] 연결 테스트 실패 ({ip}:{port}): {ex.Message}");
            System.Windows.MessageBox.Show(
                $"{ip}:{port}에 접속할 수 없습니다.\n\n확인 사항:\n1) 데스크탑에서 Host가 실행 중인지\n2) 데스크탑에서 '사설망 방화벽'을 실행했는지\n3) 두 망이 서로 분리된 회선이 아닌지 확인하세요.\n\n오류: {ex.Message}",
                "연결 테스트 실패",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            DiagnoseButton.IsEnabled = true;
        }
    }

    private void ResetTrust_Click(object sender, RoutedEventArgs e)
    {
        _config.PairedServers.Clear();
        _config.TrustedServerFingerprints.Clear();
        SaveCurrentConfig();
        RefreshClientPairingUi();
        AppendLog($"[{DateTime.Now:HH:mm:ss}] 저장된 페어링 및 서버 인증서 신뢰 목록을 초기화했습니다.");
    }

    private void FirewallButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryParsePorts(HostTcpPortBox.Text, HostUdpPortBox.Text, out int tcpPort, out int udpPort)) return;
        var (ok, message) = NetworkHelper.EnsureFirewallRules(tcpPort, udpPort);
        AppendLog($"[{DateTime.Now:HH:mm:ss}] {message}");
        System.Windows.MessageBox.Show(
            message,
            ok ? "사설망 방화벽 설정 완료" : "방화벽 설정 안내",
            MessageBoxButton.OK,
            ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private async void CheckGitHubUpdate_Click(object sender, RoutedEventArgs e)
    {
        SaveCurrentConfig();
        await CheckGitHubUpdateAsync(silentIfUpToDate: false);
    }

    private async Task CheckGitHubUpdateAsync(bool silentIfUpToDate)
    {
        string repo = GitHubRepoBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(repo))
        {
            if (!silentIfUpToDate)
            {
                ShowError("GitHub 저장소(예: username/LanKvm)를 먼저 입력하세요.");
            }
            return;
        }

        CheckGitHubButton.IsEnabled = false;
        try
        {
            AppendLog($"[{DateTime.Now:HH:mm:ss}] GitHub 릴리즈 확인 중 ({repo})...");
            GitHubReleaseInfo? release = await AppUpdater.CheckGitHubLatestAsync(repo);
            string currentVer = AppUpdater.GetCurrentVersionString();

            if (release is null)
            {
                if (!silentIfUpToDate)
                {
                    System.Windows.MessageBox.Show("최신 릴리즈에서 LanKvm.exe 에셋을 찾을 수 없습니다.", "업데이트 확인", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                return;
            }

            if (!AppUpdater.IsNewerVersion(release.TagVersion, currentVer))
            {
                AppendLog($"[{DateTime.Now:HH:mm:ss}] 현재 최신 버전입니다 (v{currentVer}).");
                if (!silentIfUpToDate)
                {
                    System.Windows.MessageBox.Show($"현재 최신 버전입니다 (v{currentVer}).", "업데이트 확인", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                return;
            }

            var answer = System.Windows.MessageBox.Show(
                $"새 버전({release.TagVersion})이 있습니다! (현재: v{currentVer})\n지금 다운로드하여 자동 업데이트하고 재시작할까요?",
                "GitHub 업데이트 발견",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (answer != MessageBoxResult.Yes) return;

            AppendLog($"[{DateTime.Now:HH:mm:ss}] {release.TagVersion} 다운로드 중...");
            string stagedPath = await AppUpdater.DownloadGitHubUpdateAsync(release);
            AppendLog($"[{DateTime.Now:HH:mm:ss}] 다운로드 및 검증 완료. 재시작합니다...");
            ApplyStagedUpdateAndRestart(stagedPath);
        }
        catch (Exception ex)
        {
            AppendLog($"[{DateTime.Now:HH:mm:ss}] GitHub 업데이트 확인 실패: {ex.Message}");
            if (!silentIfUpToDate)
            {
                System.Windows.MessageBox.Show($"업데이트 확인 오류: {ex.Message}", "업데이트 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        finally
        {
            CheckGitHubButton.IsEnabled = true;
        }
    }

    private void ApplyStagedUpdateAndRestart(string stagedExePath)
    {
        try
        {
            bool restartMinimized = !IsVisible;
            AppUpdater.LaunchApplyUpdateAndExit(stagedExePath, restartMinimized);
            ExitApplication();
        }
        catch (Exception ex)
        {
            AppendLog($"[{DateTime.Now:HH:mm:ss}] 업데이트 적용 실패: {ex.Message}");
        }
    }

    private void CopyPrimaryIp_Click(object sender, RoutedEventArgs e)
    {
        string? ip = NetworkHelper.GetPrimaryIPv4Address();
        if (!string.IsNullOrEmpty(ip))
        {
            System.Windows.Clipboard.SetText(ip);
            AppendLog($"[{DateTime.Now:HH:mm:ss}] 기본 IPv4 주소 복사됨: {ip}");
        }
    }

    private void ElevateButton_Click(object sender, RoutedEventArgs e)
    {
        SaveCurrentConfig();
        if (NetworkHelper.RestartAsAdministrator())
        {
            ExitApplication();
        }
    }

    private void ApplyHostStatus(HostStatusSnapshot snap)
    {
        _lastHostSnap = snap;

        TrayDotState trayState = snap.IsRemoteControlling
            ? TrayDotState.Remote
            : (snap.IsClientConnected ? TrayDotState.Connected : TrayDotState.Connecting);
        SetTrayState(trayState);
        SetTrayTooltip($"LanKvm Host — {snap.StatusMessage}");

        if (!IsVisible) return;

        if (snap.IsPinPairingOpen)
        {
            HostPairingStateLabel.Text = snap.PairedDeviceCount == 0
                ? "페어링 PIN 번호 (최초 1회만 노트북에 입력)"
                : $"새 기기 페어링 창 열림 (등록 {snap.PairedDeviceCount}대)";
            HostPinText.Text = snap.Pin;
            HostPinText.Foreground = BrushTextBlue;
        }
        else
        {
            HostPairingStateLabel.Text = $"보안 잠금됨 — 등록 기기 {snap.PairedDeviceCount}대 자동 인증 (새 기기 추가 시 우측 버튼)";
            HostPinText.Text = "잠금됨";
            HostPinText.Foreground = BrushTextGreen;
        }

        HostFingerprintText.Text = $"지문: {snap.CertFingerprintShort}";
        StatusDetailText.Text = snap.StatusMessage;

        if (snap.IsRemoteControlling)
        {
            SetStatusBadge("원격 제어 중", BrushBlue);
        }
        else if (snap.IsClientConnected)
        {
            SetStatusBadge("노트북 연결됨", BrushGreen);
        }
        else
        {
            SetStatusBadge("연결 대기 중", BrushSlate);
        }

        string channel = snap.IsClientConnected
            ? (snap.IsUdpActive ? "UDP (AES-GCM)" : "TCP 폴백")
            : "-";
        string rtt = snap.IsClientConnected ? $"{snap.RttMs}ms" : "-";
        HostMetricsText.Text = $"채널: {channel} | RTT: {rtt}";
    }

    private void ApplyClientStatus(ClientStatusSnapshot snap)
    {
        _lastClientSnap = snap;

        TrayDotState trayState = snap.IsControlledByHost
            ? TrayDotState.Remote
            : (snap.IsConnected ? TrayDotState.Connected : ((snap.IsConnecting || snap.IsAutoReconnecting) ? TrayDotState.Connecting : TrayDotState.Idle));
        SetTrayState(trayState);
        SetTrayTooltip($"LanKvm Client — {snap.StatusMessage}");

        if (!IsVisible) return;

        StatusDetailText.Text = snap.StatusMessage;

        if (snap.IsControlledByHost)
        {
            SetStatusBadge("원격 제어 수신 중", BrushBlue);
        }
        else if (snap.IsConnected)
        {
            SetStatusBadge("Host 연결됨", BrushGreen);
        }
        else if (snap.IsConnecting || snap.IsAutoReconnecting)
        {
            SetStatusBadge("자동 연결 대기 중", BrushAmber);
            ClientConnectButton.IsEnabled = false;
            ClientDisconnectButton.IsEnabled = true;
            HostRoleRadio.IsEnabled = false;
            ClientRoleRadio.IsEnabled = false;
        }
        else
        {
            SetStatusBadge("연결 안 됨", BrushSlate);
            ClientConnectButton.IsEnabled = true;
            ClientDisconnectButton.IsEnabled = false;
            HostRoleRadio.IsEnabled = true;
            ClientRoleRadio.IsEnabled = true;
        }

        ClientMetricsText.Text = snap.IsConnected
            ? $"모션 채널: {(snap.IsUdpActive ? "UDP (AES-GCM)" : "TCP 폴백")}"
            : "모션 채널: -";
    }

    private void SetTrayTooltip(string text)
    {
        string truncated = text.Length <= 63 ? text : text[..63];
        if (!string.Equals(_lastTrayTooltip, truncated, StringComparison.Ordinal))
        {
            _lastTrayTooltip = truncated;
            _trayIcon.Text = truncated;
        }
    }

    private void SetStatusBadge(string text, SolidColorBrush bgBrush)
    {
        StatusBadgeText.Text = text;
        StatusBadge.Background = bgBrush;
    }

    private void StopAllSessions()
    {
        _hostSession?.Dispose();
        _hostSession = null;

        _clientSession?.Dispose();
        _clientSession = null;

        _lastHostSnap = null;
        _lastClientSnap = null;

        HostStartButton.IsEnabled = true;
        HostStopButton.IsEnabled = false;
        ForceLocalButton.IsEnabled = false;
        OpenPairingButton.IsEnabled = false;
        ClientConnectButton.IsEnabled = true;
        ClientDisconnectButton.IsEnabled = false;
        HostRoleRadio.IsEnabled = true;
        ClientRoleRadio.IsEnabled = true;

        SetStatusBadge("대기 중", BrushIdle);
        StatusDetailText.Text = "역할을 선택하고 시작 버튼을 누르세요.";
        HostMetricsText.Text = "채널: - | RTT: -";
        ClientMetricsText.Text = "모션 채널: -";
        HostPinText.Text = "------";
        HostFingerprintText.Text = "지문: -";
        SetTrayState(TrayDotState.Idle);
        SetTrayTooltip("LanKvm — 대기 중");
    }

    private void AppendLog(string line)
    {
        _logLines.Add(line);
        if (_logLines.Count > 80)
        {
            _logLines.RemoveAt(0);
        }

        if (IsVisible)
        {
            LogTextBox.Text = string.Join(Environment.NewLine, _logLines);
            LogTextBox.ScrollToEnd();
            _logDirty = false;
        }
        else
        {
            _logDirty = true;
        }
    }

    private void SaveCurrentConfig()
    {
        _config.Role = HostRoleRadio.IsChecked == true ? AppRole.Host : AppRole.Client;
        _config.HostIp = ClientHostIpBox.Text.Trim();
        _config.SwitchEdge = GetSelectedEdge();
        _config.ClientSensitivity = Math.Round(SensitivitySlider.Value, 1);
        _config.ClipboardSyncEnabled = ClipboardCheck.IsChecked == true;
        _config.AutoStartService = AutoStartServiceCheck.IsChecked == true;
        _config.StartWithWindows = StartWithWindowsCheck.IsChecked == true;
        _config.AllowPrivateNetworksOnly = PrivateNetOnlyCheck.IsChecked == true;
        _config.AutoSyncUpdateFromHost = AutoSyncHostCheck.IsChecked == true;
        _config.GitHubRepo = GitHubRepoBox.Text.Trim();
        _config.CheckGitHubUpdatesOnStart = CheckGitHubOnStartCheck.IsChecked == true;

        string tcpStr = _config.Role == AppRole.Host ? HostTcpPortBox.Text : ClientTcpPortBox.Text;
        string udpStr = _config.Role == AppRole.Host ? HostUdpPortBox.Text : ClientUdpPortBox.Text;
        if (int.TryParse(tcpStr, out int tcpPort)) _config.TcpPort = tcpPort;
        if (int.TryParse(udpStr, out int udpPort)) _config.UdpPort = udpPort;
        if (int.TryParse(ResistanceBox.Text, out int res)) _config.EdgeResistancePx = res;

        ConfigStore.Save(_config);
    }

    private ScreenEdge GetSelectedEdge()
    {
        if (EdgeCombo.SelectedItem is ComboBoxItem item &&
            Enum.TryParse<ScreenEdge>(item.Tag?.ToString(), out ScreenEdge edge))
        {
            return edge;
        }
        return ScreenEdge.Right;
    }

    private static bool TryParsePorts(string tcpStr, string udpStr, out int tcpPort, out int udpPort)
    {
        tcpPort = 24800;
        udpPort = 24801;
        if (!int.TryParse(tcpStr, out tcpPort) || tcpPort is < 1024 or > 65535 ||
            !int.TryParse(udpStr, out udpPort) || udpPort is < 1024 or > 65535 ||
            tcpPort == udpPort)
        {
            ShowError("TCP와 UDP 포트는 서로 다른 1024~65535 범위의 포트 번호를 입력하세요.");
            return false;
        }
        return true;
    }

    private static void ShowError(string message) =>
        System.Windows.MessageBox.Show(message, "입력 확인", MessageBoxButton.OK, MessageBoxImage.Warning);

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();

        if (_lastHostSnap is not null) ApplyHostStatus(_lastHostSnap);
        if (_lastClientSnap is not null) ApplyClientStatus(_lastClientSnap);
        if (_logDirty)
        {
            LogTextBox.Text = string.Join(Environment.NewLine, _logLines);
            LogTextBox.ScrollToEnd();
            _logDirty = false;
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_allowExit && MinimizeToTrayCheck.IsChecked == true)
        {
            e.Cancel = true;
            Hide();
            NetworkHelper.TrimBackgroundMemory();
            return;
        }

        ForceCleanup();
        System.Windows.Application.Current.Shutdown();
    }

    private void ExitApplication()
    {
        _allowExit = true;
        ForceCleanup();
        System.Windows.Application.Current.Shutdown();
    }

    public void ForceCleanup()
    {
        SaveCurrentConfig();
        StopAllSessions();
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        foreach (var icon in _trayIcons.Values)
        {
            icon.Dispose();
        }
        _trayIcons.Clear();
    }
}
