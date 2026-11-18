using System.ComponentModel;
using System.Drawing;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
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
    private static readonly SolidColorBrush BrushTextWhite = CreateFrozenBrush(255, 255, 255);
    private static readonly SolidColorBrush BrushTextMuted = CreateFrozenBrush(148, 163, 184);
    private static readonly SolidColorBrush BrushTextBlue = CreateFrozenBrush(56, 189, 248);
    private static readonly SolidColorBrush BrushTextGreen = CreateFrozenBrush(74, 222, 128);
    private static readonly SolidColorBrush BrushTextAmber = CreateFrozenBrush(251, 191, 36);
    private static readonly SolidColorBrush BrushAdminOk = CreateFrozenBrush(20, 83, 45);
    private static readonly SolidColorBrush BrushAdminNormal = CreateFrozenBrush(30, 58, 95);

    private static readonly CubicEase PillEase = new() { EasingMode = EasingMode.EaseOut };

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
    private uint _showWindowMessage;
    private bool _isHostRole = true;
    private bool _isSettingsOpen;
    private bool _logDirty;
    private bool _allowExit;
    private bool _cleanedUp;
    private bool _initialized;

    public MainWindow(bool startMinimized = false)
    {
        InitializeComponent();

        _config = ConfigStore.Load();
        VersionText.Text = $"v{AppUpdater.GetCurrentVersionString()}";

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
            if (_isHostRole)
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

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);

        _showWindowMessage = Win32Interop.RegisterWindowMessage(App.ShowWindowBroadcastName);
        var helper = new WindowInteropHelper(this);
        IntPtr hwnd = helper.Handle;
        if (hwnd != IntPtr.Zero && _showWindowMessage != 0)
        {
            Win32Interop.ChangeWindowMessageFilterEx(hwnd, _showWindowMessage, Win32Interop.MSGFLT_ALLOW, IntPtr.Zero);
            HwndSource.FromHwnd(hwnd)?.AddHook(WndProcHook);
        }
    }

    private IntPtr WndProcHook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (_showWindowMessage != 0 && (uint)msg == _showWindowMessage)
        {
            RestoreFromTray();
            handled = true;
        }
        return IntPtr.Zero;
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
        menu.Items.Add("경계 잠금 토글", null, (_, _) => Dispatcher.Invoke(ToggleEdgeLockFromTray));
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
        _isHostRole = _config.Role == AppRole.Host;

        TcpPortBox.Text = _config.TcpPort.ToString();
        UdpPortBox.Text = _config.UdpPort.ToString();
        ResistanceBox.Text = _config.EdgeResistancePx.ToString();

        ClientHostIpBox.Text = _config.HostIp;
        SensitivitySlider.Value = Math.Clamp(_config.ClientSensitivity, 0.3, 2.5);
        SensitivityLabel.Text = $"{SensitivitySlider.Value:0.0}x";

        AutoStartServiceCheck.IsChecked = _config.AutoStartService;
        StartWithWindowsCheck.IsChecked = NetworkHelper.IsStartWithWindowsEnabled() || _config.StartWithWindows;
        PrivateNetOnlyCheck.IsChecked = _config.AllowPrivateNetworksOnly;
        ClipboardCheck.IsChecked = _config.ClipboardSyncEnabled;
        AutoLockFullscreenCheck.IsChecked = _config.AutoLockOnFullscreen;
        LockScreenEdgeCheck.IsChecked = _config.LockScreenEdge;
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

        foreach (ComboBoxItem item in SwitchHotkeyCombo.Items)
        {
            if (string.Equals(item.Tag?.ToString(), _config.SwitchHotkey.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                SwitchHotkeyCombo.SelectedItem = item;
                break;
            }
        }

        ApplyRoleVisuals(_isHostRole, animate: false);
        UpdateHostSummaryText(_config.TrustedClients.Count, "-");
        RefreshClientPairingUi();
        UpdateEdgeLockChip();
        UpdateFooterHint();
    }

    private void RefreshEnvironmentInfo()
    {
        string? primaryIp = NetworkHelper.GetPrimaryIPv4Address();
        IReadOnlyList<string> ips = NetworkHelper.GetLocalIPv4Addresses();
        if (!string.IsNullOrWhiteSpace(primaryIp))
        {
            LocalIpTextBox.Text = ips.Count > 1 ? $"{primaryIp} (+{ips.Count - 1})" : primaryIp;
        }
        else
        {
            LocalIpTextBox.Text = ips.Count > 0 ? ips[0] : "감지된 IPv4 주소 없음";
        }
        LocalIpTextBox.ToolTip = ips.Count > 0 ? string.Join(Environment.NewLine, ips) : null;

        bool isAdmin = NetworkHelper.IsRunAsAdministrator();
        AdminBadgeText.Text = isAdmin ? "권한: 관리자 권한" : "권한: 일반 권한";
        AdminBadge.Background = isAdmin ? BrushAdminOk : BrushAdminNormal;
        ElevateButton.Visibility = isAdmin ? Visibility.Collapsed : Visibility.Visible;
    }

    private void SettingsToggle_Click(object sender, RoutedEventArgs e)
    {
        _isSettingsOpen = !_isSettingsOpen;
        MainPairingView.Visibility = _isSettingsOpen ? Visibility.Collapsed : Visibility.Visible;
        SettingsView.Visibility = _isSettingsOpen ? Visibility.Visible : Visibility.Collapsed;
        SettingsToggleButton.Content = _isSettingsOpen ? "← 돌아가기" : "⚙ 설정";

        if (_isSettingsOpen)
        {
            SettingsView.ScrollToTop();
            SyncDeferredLogsIfVisible();
        }
    }

    private void DesktopRole_Click(object sender, RoutedEventArgs e) => SelectRole(isHost: true);

    private void LaptopRole_Click(object sender, RoutedEventArgs e) => SelectRole(isHost: false);

    private void SelectRole(bool isHost)
    {
        if (!_initialized || _isHostRole == isHost) return;
        _isHostRole = isHost;
        ApplyRoleVisuals(isHost, animate: true);
        UpdateFooterHint();
        SaveCurrentConfig();

        if (!isHost &&
            _config.AutoStartService &&
            _clientSession is null &&
            _hostSession is null &&
            IsCurrentClientEndpointPaired())
        {
            StartClientCore();
        }
    }

    private void RolePillTrack_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        PositionRolePillThumb(_isHostRole, animate: false);
    }

    private void ApplyRoleVisuals(bool isHost, bool animate)
    {
        DesktopRoleText.Foreground = isHost ? BrushTextWhite : BrushTextMuted;
        LaptopRoleText.Foreground = isHost ? BrushTextMuted : BrushTextWhite;
        RoleSubtitleText.Text = isHost
            ? "내 마우스·키보드로 옆 노트북을 함께 제어합니다"
            : "데스크탑에 연결하여 제어를 받는 노트북입니다";

        HostPanel.Visibility = isHost ? Visibility.Visible : Visibility.Collapsed;
        ClientPanel.Visibility = isHost ? Visibility.Collapsed : Visibility.Visible;
        PositionRolePillThumb(isHost, animate);
    }

    private void PositionRolePillThumb(bool isHost, bool animate)
    {
        double halfWidth = RolePillTrack.ActualWidth / 2.0;
        if (halfWidth <= 0) return;

        double targetX = isHost ? 0.0 : halfWidth;
        if (!animate || !IsVisible)
        {
            RolePillTransform.BeginAnimation(TranslateTransform.XProperty, null);
            RolePillTransform.X = targetX;
            return;
        }

        var anim = new DoubleAnimation(targetX, TimeSpan.FromMilliseconds(210))
        {
            EasingFunction = PillEase
        };
        RolePillTransform.BeginAnimation(TranslateTransform.XProperty, anim);
    }

    private void SetSessionLockState(bool active)
    {
        RolePillContainer.IsEnabled = !active;
        RolePillContainer.Opacity = active ? 0.6 : 1.0;
        TcpPortBox.IsEnabled = !active;
        UdpPortBox.IsEnabled = !active;
    }

    private void PortBox_Changed(object sender, TextChangedEventArgs e)
    {
        if (!_initialized) return;
        ClientEndpoint_Changed(sender, e);
    }

    private void ClientEndpoint_Changed(object sender, TextChangedEventArgs e)
    {
        if (!_initialized) return;
        RefreshClientPairingUi();
        if (!_isHostRole &&
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
        string key = $"{ClientHostIpBox.Text.Trim()}:{TcpPortBox.Text.Trim()}";
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
            ClientPinEntryPanel.Visibility = Visibility.Collapsed;
            ClientPairedReadyPanel.Visibility = Visibility.Visible;
        }
        else
        {
            ClientPairingStatusText.Text = "최초 1회 PIN 입력 필요 (이후 자동 연결)";
            ClientPairingStatusText.Foreground = BrushTextAmber;
            ClientPinEntryPanel.Visibility = Visibility.Visible;
            ClientPairedReadyPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void HostSetting_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!_initialized) return;
        ScreenEdge edge = GetSelectedEdge();
        SwitchHotkeyMode hotkey = GetSelectedHotkey();
        _config.SwitchEdge = edge;
        _config.SwitchHotkey = hotkey;
        if (_hostSession is not null)
        {
            _hostSession.SwitchEdge = edge;
            _hostSession.SwitchHotkey = hotkey;
        }
        UpdateFooterHint();
        SaveCurrentConfig();
    }

    private void HostOptionCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (!_initialized) return;
        bool autoLockFs = AutoLockFullscreenCheck.IsChecked == true;
        bool lockEdge = LockScreenEdgeCheck.IsChecked == true;
        _config.AutoLockOnFullscreen = autoLockFs;
        _config.LockScreenEdge = lockEdge;
        if (_hostSession is not null)
        {
            _hostSession.AutoLockOnFullscreen = autoLockFs;
            _hostSession.LockScreenEdge = lockEdge;
        }
        UpdateEdgeLockChip();
        UpdateFooterHint();
        SaveCurrentConfig();
    }

    private void UpdateEdgeLockChip()
    {
        HostEdgeLockChip.Visibility = LockScreenEdgeCheck.IsChecked == true
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void UpdateFooterHint()
    {
        if (!_isHostRole)
        {
            MainFooterHintText.Text = "상세 옵션은 우측 상단 ⚙ 설정";
            return;
        }

        string edgeName = GetSelectedEdge() switch
        {
            ScreenEdge.Left => "왼쪽",
            ScreenEdge.Right => "오른쪽",
            ScreenEdge.Top => "위",
            ScreenEdge.Bottom => "아래",
            _ => "오른쪽"
        };
        string hotkeyName = GetSelectedHotkey() switch
        {
            SwitchHotkeyMode.CtrlAltSpace => "Ctrl+Alt+Space",
            SwitchHotkeyMode.ScrollLock => "ScrollLock",
            SwitchHotkeyMode.Pause => "Pause",
            _ => "단축키 없음"
        };
        MainFooterHintText.Text = LockScreenEdgeCheck.IsChecked == true
            ? $"경계 잠금 · {hotkeyName}"
            : $"{edgeName} 경계 · {hotkeyName}";
    }

    private void ToggleEdgeLockFromTray()
    {
        bool next = LockScreenEdgeCheck.IsChecked != true;
        LockScreenEdgeCheck.IsChecked = next;
        AppendLog($"[{DateTime.Now:HH:mm:ss}] {(next ? "경계 이동 잠금됨 (단축키 전환만 활성)" : "경계 이동 잠금 해제됨")}");
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
        if (!TryParsePorts(TcpPortBox.Text, UdpPortBox.Text, out int tcpPort, out int udpPort)) return;
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
                GetSelectedHotkey(),
                AutoLockFullscreenCheck.IsChecked == true,
                LockScreenEdgeCheck.IsChecked == true,
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
            SetSessionLockState(true);

            UpdateHostSummaryText(_config.TrustedClients.Count, _hostSession.CertFingerprintShort);
        }
        catch (Exception ex)
        {
            ShowError($"Host 시작 실패: {ex.Message}");
            StopAllSessions();
        }
    }

    private void HostStop_Click(object sender, RoutedEventArgs e) => StopAllSessions();

    private void ForceLocal_Click(object sender, RoutedEventArgs e) => _hostSession?.ForceReturnToLocal();

    private void OpenPairing_Click(object sender, RoutedEventArgs e) =>
        _hostSession?.OpenPairingWindow(TimeSpan.FromMinutes(3));

    private void ClearPairedClients_Click(object sender, RoutedEventArgs e)
    {
        _config.TrustedClients.Clear();
        SaveCurrentConfig();
        _hostSession?.ClearTrustedClients();
        UpdateHostSummaryText(0, _hostSession?.CertFingerprintShort ?? "-");
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
        if (!TryParsePorts(TcpPortBox.Text, UdpPortBox.Text, out int tcpPort, out int udpPort)) return;

        string key = $"{hostIp}:{tcpPort}";
        _config.PairedServers.TryGetValue(key, out PairedServerRecord? pairedServer);
        bool hasValidToken = pairedServer is not null &&
                             DpapiHelper.TryUnprotectFromBase64(pairedServer.EncryptedTokenBase64) is { Length: > 0 };

        string pin = ClientPinBox.Text.Trim();
        if (!hasValidToken && (pin.Length != 6 || !pin.All(char.IsDigit)))
        {
            ShowError("최초 1회 연결을 위해 데스크탑 화면의 6자리 숫자 PIN을 입력하세요.");
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
        SetSessionLockState(true);
    }

    private void ClientDisconnect_Click(object sender, RoutedEventArgs e) => StopAllSessions();

    private async void DiagnoseConnection_Click(object sender, RoutedEventArgs e)
    {
        string ip = ClientHostIpBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(ip))
        {
            ShowError("데스크탑(Host) IP 주소를 먼저 입력하세요.");
            return;
        }
        if (!int.TryParse(TcpPortBox.Text, out int port))
        {
            ShowError("⚙ 설정에서 유효한 TCP 포트를 입력하세요.");
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
                "연결 확인 완료",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendLog($"[{DateTime.Now:HH:mm:ss}] 연결 테스트 실패 ({ip}:{port}): {ex.Message}");
            System.Windows.MessageBox.Show(
                $"{ip}:{port}에 접속할 수 없습니다.\n\n확인 사항:\n1) 데스크탑에서 '서버 시작' 상태인지\n2) 데스크탑 ⚙ 설정에서 '사설망 방화벽 허용'을 실행했는지\n3) 두 기기가 같은 공유기(사설망)에 있는지 확인하세요.\n\n오류: {ex.Message}",
                "연결 확인 실패",
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
        if (_clientSession is not null)
        {
            StopAllSessions();
        }
        _config.PairedServers.Clear();
        _config.TrustedServerFingerprints.Clear();
        SaveCurrentConfig();
        RefreshClientPairingUi();
        AppendLog($"[{DateTime.Now:HH:mm:ss}] 저장된 페어링 및 서버 인증서 신뢰 목록을 초기화했습니다.");
    }

    private void FirewallButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryParsePorts(TcpPortBox.Text, UdpPortBox.Text, out int tcpPort, out int udpPort)) return;
        var (ok, message) = NetworkHelper.EnsureFirewallRules(tcpPort, udpPort);
        AppendLog($"[{DateTime.Now:HH:mm:ss}] {message}");
        System.Windows.MessageBox.Show(
            message,
            ok ? "방화벽 설정 완료" : "방화벽 설정 안내",
            MessageBoxButton.OK,
            ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void RemoveFirewallButton_Click(object sender, RoutedEventArgs e)
    {
        var (ok, message) = NetworkHelper.RemoveFirewallRules();
        AppendLog($"[{DateTime.Now:HH:mm:ss}] {message}");
        System.Windows.MessageBox.Show(
            message,
            ok ? "방화벽 규칙 제거" : "방화벽 규칙 제거 안내",
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
                ShowError("GitHub 저장소(예: bugea0002/LanKvm)를 먼저 입력하세요.");
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

    private void UpdateHostSummaryText(int pairedCount, string certFpShort)
    {
        HostPairedSummaryText.Text = $"등록 기기: {pairedCount}대 · 지문 {certFpShort}";
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
                : $"새 기기 페어링 허용 중 (등록 {snap.PairedDeviceCount}대)";
            HostPinText.Text = snap.Pin;
            HostPinText.Foreground = BrushTextBlue;
        }
        else
        {
            HostPairingStateLabel.Text = $"보안 잠금됨 — 등록 기기 {snap.PairedDeviceCount}대 자동 인증";
            HostPinText.Text = "잠금됨";
            HostPinText.Foreground = BrushTextGreen;
        }

        UpdateHostSummaryText(snap.PairedDeviceCount, snap.CertFingerprintShort);
        StatusDetailText.Text = snap.StatusMessage;

        if (snap.IsRemoteControlling)
        {
            SetStatusBadge("원격 제어 중", BrushBlue);
        }
        else if (snap.IsClientConnected)
        {
            SetStatusBadge("연결됨", BrushGreen);
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
            SetStatusBadge("원격 제어 중", BrushBlue);
        }
        else if (snap.IsConnected)
        {
            SetStatusBadge("연결됨", BrushGreen);
        }
        else if (snap.IsConnecting || snap.IsAutoReconnecting)
        {
            SetStatusBadge("연결 대기 중", BrushAmber);
            ClientConnectButton.IsEnabled = false;
            ClientDisconnectButton.IsEnabled = true;
            SetSessionLockState(true);
        }
        else
        {
            SetStatusBadge("연결 안 됨", BrushSlate);
            ClientConnectButton.IsEnabled = true;
            ClientDisconnectButton.IsEnabled = false;
            SetSessionLockState(false);
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
        SetSessionLockState(false);

        SetStatusBadge("대기 중", BrushIdle);
        StatusDetailText.Text = "역할을 확인하고 시작 버튼을 누르세요.";
        HostMetricsText.Text = "채널: - | RTT: -";
        ClientMetricsText.Text = "모션 채널: -";
        HostPinText.Text = "------";
        UpdateHostSummaryText(_config.TrustedClients.Count, "-");
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

        if (IsVisible && _isSettingsOpen)
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

    private void SyncDeferredLogsIfVisible()
    {
        if (!_logDirty || !IsVisible || !_isSettingsOpen) return;
        LogTextBox.Text = string.Join(Environment.NewLine, _logLines);
        LogTextBox.ScrollToEnd();
        _logDirty = false;
    }

    private void SaveCurrentConfig()
    {
        _config.Role = _isHostRole ? AppRole.Host : AppRole.Client;
        _config.HostIp = ClientHostIpBox.Text.Trim();
        _config.SwitchEdge = GetSelectedEdge();
        _config.SwitchHotkey = GetSelectedHotkey();
        _config.AutoLockOnFullscreen = AutoLockFullscreenCheck.IsChecked == true;
        _config.LockScreenEdge = LockScreenEdgeCheck.IsChecked == true;
        _config.ClientSensitivity = Math.Round(SensitivitySlider.Value, 1);
        _config.ClipboardSyncEnabled = ClipboardCheck.IsChecked == true;
        _config.AutoStartService = AutoStartServiceCheck.IsChecked == true;
        _config.StartWithWindows = StartWithWindowsCheck.IsChecked == true;
        _config.AllowPrivateNetworksOnly = PrivateNetOnlyCheck.IsChecked == true;
        _config.AutoSyncUpdateFromHost = AutoSyncHostCheck.IsChecked == true;
        _config.GitHubRepo = GitHubRepoBox.Text.Trim();
        _config.CheckGitHubUpdatesOnStart = CheckGitHubOnStartCheck.IsChecked == true;

        if (int.TryParse(TcpPortBox.Text, out int tcpPort)) _config.TcpPort = tcpPort;
        if (int.TryParse(UdpPortBox.Text, out int udpPort)) _config.UdpPort = udpPort;
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

    private SwitchHotkeyMode GetSelectedHotkey()
    {
        if (SwitchHotkeyCombo.SelectedItem is ComboBoxItem item &&
            Enum.TryParse<SwitchHotkeyMode>(item.Tag?.ToString(), out SwitchHotkeyMode mode))
        {
            return mode;
        }
        return SwitchHotkeyMode.CtrlAltSpace;
    }

    private static bool TryParsePorts(string tcpStr, string udpStr, out int tcpPort, out int udpPort)
    {
        tcpPort = 24800;
        udpPort = 24801;
        if (!int.TryParse(tcpStr, out tcpPort) || tcpPort is < 1024 or > 65535 ||
            !int.TryParse(udpStr, out udpPort) || udpPort is < 1024 or > 65535 ||
            tcpPort == udpPort)
        {
            ShowError("⚙ 설정의 TCP/UDP 포트는 서로 다른 1024~65535 번호여야 합니다.");
            return false;
        }
        return true;
    }

    private static void ShowError(string message) =>
        System.Windows.MessageBox.Show(message, "입력 확인", MessageBoxButton.OK, MessageBoxImage.Warning);

    public void RestoreFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        // Brief topmost pulse guarantees the restored window surfaces cleanly over background windows.
        Topmost = true;
        Topmost = false;
        Activate();

        PositionRolePillThumb(_isHostRole, animate: false);
        if (_lastHostSnap is not null) ApplyHostStatus(_lastHostSnap);
        if (_lastClientSnap is not null) ApplyClientStatus(_lastClientSnap);
        SyncDeferredLogsIfVisible();
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
        if (_cleanedUp) return;
        _cleanedUp = true;

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
