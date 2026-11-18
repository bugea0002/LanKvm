using System.Drawing;
using System.Windows.Forms;
using LanKvm.Core.Native;

namespace LanKvm.Core.Input;

/// <summary>
/// Non-activating layered topmost overlay that hides the local cursor with an
/// application-owned blank cursor without mutating global Windows system cursors.
/// </summary>
internal sealed class CursorHiderOverlay : Form
{
    private readonly IntPtr _blankCursorHandle;
    private readonly Cursor _blankCursor;

    public CursorHiderOverlay()
    {
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        TopMost = true;
        BackColor = Color.Black;
        Opacity = 0.01;
        Enabled = true;

        byte[] andPlane = new byte[128];
        Array.Fill(andPlane, (byte)0xFF);
        byte[] xorPlane = new byte[128];
        _blankCursorHandle = Win32Interop.CreateCursor(IntPtr.Zero, 0, 0, 32, 32, andPlane, xorPlane);
        _blankCursor = _blankCursorHandle != IntPtr.Zero ? new Cursor(_blankCursorHandle) : Cursors.Default;
        Cursor = _blankCursor;
    }

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams cp = base.CreateParams;
            cp.ExStyle |= Win32Interop.WS_EX_TOOLWINDOW |
                          Win32Interop.WS_EX_TOPMOST |
                          Win32Interop.WS_EX_NOACTIVATE |
                          Win32Interop.WS_EX_LAYERED;
            return cp;
        }
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == Win32Interop.WM_SETCURSOR)
        {
            Cursor.Current = _blankCursor;
            m.Result = (IntPtr)1;
            return;
        }
        base.WndProc(ref m);
    }

    public void ShowOverVirtualScreen(ScreenRect bounds)
    {
        Bounds = new Rectangle(bounds.Left, bounds.Top, bounds.Width, bounds.Height);
        if (!Visible)
        {
            Show();
        }
        Cursor = _blankCursor;
    }

    public void HideOverlay()
    {
        if (Visible)
        {
            Hide();
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _blankCursor.Dispose();
        }
        if (_blankCursorHandle != IntPtr.Zero)
        {
            Win32Interop.DestroyCursor(_blankCursorHandle);
        }
        base.Dispose(disposing);
    }
}
