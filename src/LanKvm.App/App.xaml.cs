using System.Windows;
using LanKvm.Core.Update;

namespace LanKvm.App;

public partial class App : System.Windows.Application
{
    private MainWindow? _mainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (AppUpdater.HandleStartupArgs(e.Args, out bool startMinimized))
        {
            Shutdown();
            return;
        }

        _mainWindow = new MainWindow(startMinimized);
        if (!startMinimized)
        {
            _mainWindow.Show();
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _mainWindow?.ForceCleanup();
        base.OnExit(e);
    }
}
