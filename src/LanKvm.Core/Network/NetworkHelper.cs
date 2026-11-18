using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace LanKvm.Core.Network;

public static class NetworkHelper
{
    public const int SioUdpConnReset = -1744830452;
    private const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "LanKvm";

    public static void DisableUdpConnReset(Socket socket)
    {
        if (OperatingSystem.IsWindows())
        {
            socket.IOControl((IOControlCode)SioUdpConnReset, [0, 0, 0, 0], null);
        }
    }

    /// <summary>
    /// Returns true only for Loopback or RFC 1918 private IPv4 addresses (10/8, 172.16/12, 192.168/16).
    /// Blocks all external internet public IPv4 addresses.
    /// </summary>
    public static bool IsPrivateOrLoopback(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address)) return true;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            return false;
        }

        return false;
    }

    public static IReadOnlyList<string> GetLocalIPv4Addresses()
    {
        var results = new List<string>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            var props = ni.GetIPProperties();
            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                string ip = ua.Address.ToString();
                if (!ip.StartsWith("169.254.", StringComparison.Ordinal))
                {
                    results.Add($"{ip} ({ni.Name})");
                }
            }
        }
        return results;
    }

    public static string? GetPrimaryIPv4Address()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            var props = ni.GetIPProperties();
            if (props.GatewayAddresses.Count == 0) continue;

            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(ua.Address))
                {
                    return ua.Address.ToString();
                }
            }
        }
        return null;
    }

    public static bool IsRunAsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var id = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(id);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string? GetExecutableScopePath(string? processPath = null)
    {
        string? exePath = processPath ?? Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath) ||
            !exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        return exePath;
    }

    public static string BuildEnsureFirewallScript(int tcpPort, int udpPort, string? programPath = null)
    {
        // Restrict inbound traffic strictly to local/private subnets (and LanKvm.exe binary when available)
        // so public internet IPs and unrelated processes remain unaffected.
        const string allowedSubnets = "LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
        string? scopedProgram = GetExecutableScopePath(programPath ?? Environment.ProcessPath);
        string programArg = scopedProgram is null
            ? string.Empty
            : $" -Program '{scopedProgram.Replace("'", "''")}'";

        return
            "$ErrorActionPreference='Stop';" +
            "Remove-NetFirewallRule -DisplayName 'LanKvm-TCP-*','LanKvm-UDP-*' -ErrorAction SilentlyContinue;" +
            $"New-NetFirewallRule -DisplayName 'LanKvm-TCP-{tcpPort}' -Direction Inbound -Protocol TCP -LocalPort {tcpPort}{programArg} -RemoteAddress {allowedSubnets} -Action Allow -Profile Any | Out-Null;" +
            $"New-NetFirewallRule -DisplayName 'LanKvm-UDP-{udpPort}' -Direction Inbound -Protocol UDP -LocalPort {udpPort}{programArg} -RemoteAddress {allowedSubnets} -Action Allow -Profile Any | Out-Null;";
    }

    public static string BuildRemoveFirewallScript() =>
        "$ErrorActionPreference='Stop';" +
        "Remove-NetFirewallRule -DisplayName 'LanKvm-TCP-*','LanKvm-UDP-*' -ErrorAction SilentlyContinue;";

    public static (bool Success, string Message) EnsureFirewallRules(int tcpPort, int udpPort)
    {
        string script = BuildEnsureFirewallScript(tcpPort, udpPort);
        return RunElevatedPowerShell(
            script,
            $"LanKvm.exe 전용 사설망 인바운드 규칙(TCP {tcpPort} / UDP {udpPort})을 등록했습니다.",
            "방화벽 규칙 등록");
    }

    public static (bool Success, string Message) RemoveFirewallRules()
    {
        return RunElevatedPowerShell(
            BuildRemoveFirewallScript(),
            "등록된 LanKvm 방화벽 규칙을 모두 제거했습니다.",
            "방화벽 규칙 제거");
    }

    private static (bool Success, string Message) RunElevatedPowerShell(string script, string successMessage, string actionLabel)
    {
        try
        {
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}",
                UseShellExecute = true,
                Verb = IsRunAsAdministrator() ? "" : "runas",
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return (false, $"{actionLabel} 프로세스를 시작하지 못했습니다.");
            proc.WaitForExit(15000);
            return proc.ExitCode == 0
                ? (true, successMessage)
                : (false, $"{actionLabel} 실패 (종료 코드 {proc.ExitCode}).");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return (false, "관리자 권한 승격(UAC)이 취소되었습니다.");
        }
        catch (Exception ex)
        {
            return (false, $"{actionLabel} 오류: {ex.Message}");
        }
    }

    public static bool IsStartWithWindowsEnabled()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
        return key?.GetValue(RunValueName) is string s && !string.IsNullOrWhiteSpace(s);
    }

    public static (bool Success, string Message) SetStartWithWindows(bool enable)
    {
        if (!OperatingSystem.IsWindows()) return (false, "Windows에서만 지원됩니다.");
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true) ??
                                     Registry.CurrentUser.CreateSubKey(RunKeyPath);
            if (key is null) return (false, "시작 프로그램 레지스트리 키를 열 수 없습니다.");

            if (enable)
            {
                string? exePath = Environment.ProcessPath;
                if (string.IsNullOrEmpty(exePath) ||
                    Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, "단일 실행 파일(LanKvm.exe)에서 실행할 때만 자동 실행 등록이 가능합니다.");
                }
                key.SetValue(RunValueName, $"\"{exePath}\" --minimized");
                return (true, "Windows 시작 시 트레이로 자동 실행되도록 등록했습니다.");
            }
            else
            {
                key.DeleteValue(RunValueName, throwOnMissingValue: false);
                return (true, "Windows 시작 시 자동 실행을 해제했습니다.");
            }
        }
        catch (Exception ex)
        {
            return (false, $"시작 프로그램 등록 오류: {ex.Message}");
        }
    }

    public static bool RestartAsAdministrator()
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath)) return false;

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = $"--wait-pid {Environment.ProcessId}",
                UseShellExecute = true,
                Verb = "runas"
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void TrimBackgroundMemory()
    {
        try
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Optimized, blocking: false);
            if (OperatingSystem.IsWindows())
            {
                using var proc = Process.GetCurrentProcess();
                Native.Win32Interop.SetProcessWorkingSetSize(proc.Handle, new IntPtr(-1), new IntPtr(-1));
            }
        }
        catch
        {
            // Non-critical optimization
        }
    }
}
