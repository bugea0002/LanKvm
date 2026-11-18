using System.Runtime.InteropServices;
using System.Text;
using LanKvm.Core.Native;

namespace LanKvm.Core.Input;

/// <summary>
/// Detects whether the current foreground application is running in fullscreen
/// (games, borderless fullscreen, or fullscreen media) without background polling.
/// </summary>
public static class FullscreenDetector
{
    private const uint MonitorDefaultToNearest = 2;

    public static bool IsWindowCoveringMonitor(Win32Interop.RECT windowRect, Win32Interop.RECT monitorRect) =>
        windowRect.Left <= monitorRect.Left &&
        windowRect.Top <= monitorRect.Top &&
        windowRect.Right >= monitorRect.Right &&
        windowRect.Bottom >= monitorRect.Bottom;

    public static bool IsForegroundFullscreen()
    {
        IntPtr hwnd = Win32Interop.GetForegroundWindow();
        if (hwnd == IntPtr.Zero) return false;
        if (hwnd == Win32Interop.GetDesktopWindow() || hwnd == Win32Interop.GetShellWindow()) return false;
        if (!Win32Interop.IsWindowVisible(hwnd)) return false;

        _ = Win32Interop.GetWindowThreadProcessId(hwnd, out uint pid);
        if (pid == (uint)Environment.ProcessId) return false;

        var sb = new StringBuilder(64);
        int len = Win32Interop.GetClassName(hwnd, sb, sb.Capacity);
        if (len > 0)
        {
            string cls = sb.ToString();
            if (cls.Equals("Progman", StringComparison.OrdinalIgnoreCase) ||
                cls.Equals("WorkerW", StringComparison.OrdinalIgnoreCase) ||
                cls.Equals("Shell_TrayWnd", StringComparison.OrdinalIgnoreCase) ||
                cls.Equals("Shell_SecondaryTrayWnd", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        if (!Win32Interop.GetWindowRect(hwnd, out Win32Interop.RECT winRect)) return false;

        IntPtr hMon = Win32Interop.MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        if (hMon == IntPtr.Zero) return false;

        var mi = new Win32Interop.MONITORINFO { cbSize = Marshal.SizeOf<Win32Interop.MONITORINFO>() };
        if (!Win32Interop.GetMonitorInfo(hMon, ref mi)) return false;

        return IsWindowCoveringMonitor(winRect, mi.rcMonitor);
    }
}
