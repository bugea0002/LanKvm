using System.Windows;
using System.Windows.Interop;
using LanKvm.Core.Native;
using LanKvm.Core.Update;

namespace LanKvm.App;

public partial class App : System.Windows.Application
{
    private const string SingleInstanceMutexName = @"Local\LanKvm.SingleInstance.v1";
    private const string ShowWindowEventName = @"Local\LanKvm.ShowWindow.v1";
    public const string ShowWindowBroadcastName = "LanKvm.ShowExistingWindow.v1";

    private MainWindow? _mainWindow;
    private SingleInstanceGuard? _singleInstanceGuard;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (AppUpdater.HandleStartupArgs(e.Args, out bool startMinimized))
        {
            Shutdown();
            return;
        }

        if (!SingleInstanceGuard.TryAcquire(
                SingleInstanceMutexName,
                ShowWindowEventName,
                e.Args,
                notifyExistingIfDuplicate: !startMinimized,
                BroadcastShowExistingWindow,
                out _singleInstanceGuard))
        {
            Shutdown();
            return;
        }

        _mainWindow = new MainWindow(startMinimized);
        _singleInstanceGuard!.RegisterActivationCallback(() =>
        {
            Dispatcher.BeginInvoke(() => _mainWindow?.RestoreFromTray());
        });

        if (startMinimized)
        {
            // Ensure HWND + message hook exists even while hidden in tray so elevated/non-elevated
            // broadcast restore messages can still wake the window cleanly.
            new WindowInteropHelper(_mainWindow).EnsureHandle();
        }
        else
        {
            _mainWindow.Show();
        }
    }

    private static void BroadcastShowExistingWindow()
    {
        uint msg = Win32Interop.RegisterWindowMessage(ShowWindowBroadcastName);
        if (msg != 0)
        {
            Win32Interop.PostMessage(Win32Interop.HWND_BROADCAST, msg, IntPtr.Zero, IntPtr.Zero);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _mainWindow?.ForceCleanup();
        _singleInstanceGuard?.Dispose();
        _singleInstanceGuard = null;
        base.OnExit(e);
    }
}
