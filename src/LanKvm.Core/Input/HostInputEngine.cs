using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using System.Windows.Forms;
using LanKvm.Core.Native;
using LanKvm.Protocol;

namespace LanKvm.Core.Input;

public abstract record CapturedInputEvent;
public sealed record CapturedMouseButtonEvent(MouseButtonKind Button, bool IsDown) : CapturedInputEvent;
public sealed record CapturedMouseWheelEvent(int Delta, bool IsHorizontal) : CapturedInputEvent;
public sealed record CapturedKeyEvent(ushort VirtualKey, ushort ScanCode, bool IsExtended, bool IsKeyUp) : CapturedInputEvent;
public sealed record CapturedSwitchToClientEvent(ScreenEdge HostEdge, float Ratio) : CapturedInputEvent;

/// <summary>
/// Captures mouse deltas via Raw Input (WM_INPUT) and intercepts clicks/keys via
/// low-level hooks on a dedicated high-priority STA Win32 message thread.
/// Hook callbacks never perform blocking I/O.
/// </summary>
public sealed class HostInputEngine : IDisposable
{
    private readonly Channel<CapturedInputEvent> _events = Channel.CreateUnbounded<CapturedInputEvent>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });

    private readonly MotionCoalescer _motionCoalescer;
    private readonly EdgeSwitchStateMachine _stateMachine;
    private readonly Stopwatch _clock = Stopwatch.StartNew();

    private Thread? _hookThread;
    private ApplicationContext? _appContext;
    private Control? _marshalingControl;
    private RawInputWindow? _rawWindow;
    private CursorHiderOverlay? _overlay;
    private IntPtr _mouseHook;
    private IntPtr _keyboardHook;

    // Keep delegates rooted so GC never collects native hook callbacks
    private Win32Interop.LowLevelHookProc? _mouseProc;
    private Win32Interop.LowLevelHookProc? _keyboardProc;

    private volatile bool _canSwitchToRemote;
    private volatile ScreenEdge _switchEdge = ScreenEdge.Right;
    private volatile bool _disposed;

    private bool _hasLastAbs;
    private int _lastAbsX;
    private int _lastAbsY;

    public event Action? EmergencyEscapeTriggered;
    public event Action<bool>? RemoteStateChanged;
    public event Action? CursorRepositionBlocked;

    public HostInputEngine(MotionCoalescer motionCoalescer, int edgeResistancePixels = 16, long cooldownMs = 150)
    {
        _motionCoalescer = motionCoalescer;
        _stateMachine = new EdgeSwitchStateMachine(edgeResistancePixels, cooldownMs);
    }

    public ChannelReader<CapturedInputEvent> Events => _events.Reader;
    public bool IsRemote => _stateMachine.IsRemote;

    public ScreenEdge SwitchEdge
    {
        get => _switchEdge;
        set => _switchEdge = value;
    }

    public bool CanSwitchToRemote
    {
        get => _canSwitchToRemote;
        set
        {
            _canSwitchToRemote = value;
            if (!value && _stateMachine.IsRemote)
            {
                ForceReturnToLocal(0.5f);
            }
        }
    }

    public void Start()
    {
        if (_hookThread is not null) return;

        using var ready = new ManualResetEventSlim(false);
        Exception? initError = null;

        _hookThread = new Thread(() =>
        {
            try
            {
                _appContext = new ApplicationContext();
                _marshalingControl = new Control();
                _ = _marshalingControl.Handle;
                _overlay = new CursorHiderOverlay();
                _rawWindow = new RawInputWindow(HandleRawMouseInput);

                _mouseProc = MouseHookCallback;
                _keyboardProc = KeyboardHookCallback;

                IntPtr hMod = Win32Interop.GetModuleHandle(Process.GetCurrentProcess().MainModule?.ModuleName);
                _mouseHook = Win32Interop.SetWindowsHookEx(Win32Interop.WH_MOUSE_LL, _mouseProc, hMod, 0);
                _keyboardHook = Win32Interop.SetWindowsHookEx(Win32Interop.WH_KEYBOARD_LL, _keyboardProc, hMod, 0);

                if (_mouseHook == IntPtr.Zero || _keyboardHook == IntPtr.Zero)
                {
                    throw new InvalidOperationException($"Failed to install input hooks (Win32 error {Marshal.GetLastWin32Error()}).");
                }
            }
            catch (Exception ex)
            {
                initError = ex;
            }
            finally
            {
                ready.Set();
            }

            if (initError is null)
            {
                Application.Run(_appContext!);
            }
        })
        {
            Name = "LanKvm-HostInputThread",
            IsBackground = true,
            Priority = ThreadPriority.Highest
        };

        _hookThread.SetApartmentState(ApartmentState.STA);
        _hookThread.Start();
        ready.Wait();

        if (initError is not null)
        {
            throw new InvalidOperationException("Failed to initialize Host input engine.", initError);
        }
    }

    public void ForceReturnToLocal(float ratio)
    {
        if (_disposed || _appContext is null || _rawWindow is null) return;

        void Execute()
        {
            if (!_stateMachine.IsRemote) return;

            ScreenEdge edge = _switchEdge;
            _stateMachine.ResetToLocal(_clock.ElapsedMilliseconds);
            _motionCoalescer.Reset();
            _hasLastAbs = false;

            var (vLeft, vTop, vWidth, vHeight) = Win32Interop.GetVirtualScreenBounds();
            var bounds = new ScreenRect(vLeft, vTop, vWidth, vHeight);
            var (rx, ry) = EdgeSwitchStateMachine.ComputeEntryPoint(bounds, edge, ratio, insetPx: 8);
            bool moved = Win32Interop.SetCursorPos(rx, ry);
            _overlay?.HideOverlay();

            if (!moved)
            {
                CursorRepositionBlocked?.Invoke();
            }

            RemoteStateChanged?.Invoke(false);
        }

        if (_marshalingControl is { IsHandleCreated: true })
        {
            _marshalingControl.BeginInvoke(Execute);
        }
    }

    private void EnterRemoteMode(ScreenRect bounds, float ratio)
    {
        _motionCoalescer.Reset();
        _hasLastAbs = false;

        // Place overlay spanning all virtual monitors and keep cursor parked at the exit edge
        // (never jump to screen center) so return transitions never expose a centered cursor.
        _overlay?.ShowOverVirtualScreen(bounds);
        var (parkX, parkY) = EdgeSwitchStateMachine.ComputeEntryPoint(bounds, _switchEdge, ratio, insetPx: 2);
        Win32Interop.SetCursorPos(parkX, parkY);

        _events.Writer.TryWrite(new CapturedSwitchToClientEvent(_switchEdge, ratio));
        RemoteStateChanged?.Invoke(true);
    }

    private void HandleRawMouseInput(Win32Interop.RAWMOUSE mouse)
    {
        int dx = 0;
        int dy = 0;

        if ((mouse.usFlags & Win32Interop.MOUSE_MOVE_ABSOLUTE) == 0)
        {
            dx = mouse.lLastX;
            dy = mouse.lLastY;
        }
        else
        {
            var (_, _, vW, vH) = Win32Interop.GetVirtualScreenBounds();
            int absX = (int)Math.Round(mouse.lLastX / 65535.0 * vW);
            int absY = (int)Math.Round(mouse.lLastY / 65535.0 * vH);
            if (_hasLastAbs)
            {
                dx = absX - _lastAbsX;
                dy = absY - _lastAbsY;
            }
            _lastAbsX = absX;
            _lastAbsY = absY;
            _hasLastAbs = true;
        }

        if (dx == 0 && dy == 0) return;

        if (_stateMachine.IsRemote)
        {
            _motionCoalescer.AddDelta(dx, dy);
            return;
        }

        if (!_canSwitchToRemote) return;

        if (Win32Interop.GetCursorPos(out var pt))
        {
            var (vLeft, vTop, vWidth, vHeight) = Win32Interop.GetVirtualScreenBounds();
            var bounds = new ScreenRect(vLeft, vTop, vWidth, vHeight);

            if (_stateMachine.TryShouldSwitchToClient(
                    pt.X, pt.Y, dx, dy, bounds, _switchEdge, _clock.ElapsedMilliseconds, out float ratio))
            {
                EnterRemoteMode(bounds, ratio);
            }
        }
    }

    private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && _stateMachine.IsRemote)
        {
            int msg = wParam.ToInt32();
            var hookStruct = Marshal.PtrToStructure<Win32Interop.MSLLHOOKSTRUCT>(lParam);

            switch (msg)
            {
                case Win32Interop.WM_MOUSEMOVE:
                    return (IntPtr)1;
                case Win32Interop.WM_LBUTTONDOWN:
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(MouseButtonKind.Left, true));
                    return (IntPtr)1;
                case Win32Interop.WM_LBUTTONUP:
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(MouseButtonKind.Left, false));
                    return (IntPtr)1;
                case Win32Interop.WM_RBUTTONDOWN:
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(MouseButtonKind.Right, true));
                    return (IntPtr)1;
                case Win32Interop.WM_RBUTTONUP:
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(MouseButtonKind.Right, false));
                    return (IntPtr)1;
                case Win32Interop.WM_MBUTTONDOWN:
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(MouseButtonKind.Middle, true));
                    return (IntPtr)1;
                case Win32Interop.WM_MBUTTONUP:
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(MouseButtonKind.Middle, false));
                    return (IntPtr)1;
                case Win32Interop.WM_XBUTTONDOWN:
                {
                    ushort xBtn = (ushort)((hookStruct.mouseData >> 16) & 0xFFFF);
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(
                        xBtn == 2 ? MouseButtonKind.XButton2 : MouseButtonKind.XButton1, true));
                    return (IntPtr)1;
                }
                case Win32Interop.WM_XBUTTONUP:
                {
                    ushort xBtn = (ushort)((hookStruct.mouseData >> 16) & 0xFFFF);
                    _events.Writer.TryWrite(new CapturedMouseButtonEvent(
                        xBtn == 2 ? MouseButtonKind.XButton2 : MouseButtonKind.XButton1, false));
                    return (IntPtr)1;
                }
                case Win32Interop.WM_MOUSEWHEEL:
                {
                    short delta = unchecked((short)((hookStruct.mouseData >> 16) & 0xFFFF));
                    _events.Writer.TryWrite(new CapturedMouseWheelEvent(delta, false));
                    return (IntPtr)1;
                }
                case Win32Interop.WM_MOUSEHWHEEL:
                {
                    short delta = unchecked((short)((hookStruct.mouseData >> 16) & 0xFFFF));
                    _events.Writer.TryWrite(new CapturedMouseWheelEvent(delta, true));
                    return (IntPtr)1;
                }
            }
        }

        return Win32Interop.CallNextHookEx(_mouseHook, nCode, wParam, lParam);
    }

    private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && _stateMachine.IsRemote)
        {
            var kb = Marshal.PtrToStructure<Win32Interop.KBDLLHOOKSTRUCT>(lParam);
            bool isKeyUp = (kb.flags & Win32Interop.LLKHF_UP) != 0;
            bool isExtended = (kb.flags & Win32Interop.LLKHF_EXTENDED) != 0;

            // Local emergency escape: Ctrl + Alt + Esc always restores Host immediately
            if (!isKeyUp && kb.vkCode == Win32Interop.VK_ESCAPE && IsCtrlAltHeld())
            {
                _marshalingControl?.BeginInvoke(() =>
                {
                    ForceReturnToLocal(0.5f);
                    EmergencyEscapeTriggered?.Invoke();
                });
                return (IntPtr)1;
            }

            _events.Writer.TryWrite(new CapturedKeyEvent(
                (ushort)kb.vkCode,
                (ushort)kb.scanCode,
                isExtended,
                isKeyUp));
            return (IntPtr)1;
        }

        return Win32Interop.CallNextHookEx(_keyboardHook, nCode, wParam, lParam);
    }

    private static bool IsCtrlAltHeld()
    {
        bool ctrl = (Win32Interop.GetAsyncKeyState(Win32Interop.VK_LCONTROL) & 0x8000) != 0 ||
                    (Win32Interop.GetAsyncKeyState(Win32Interop.VK_RCONTROL) & 0x8000) != 0;
        bool alt = (Win32Interop.GetAsyncKeyState(Win32Interop.VK_LMENU) & 0x8000) != 0 ||
                   (Win32Interop.GetAsyncKeyState(Win32Interop.VK_RMENU) & 0x8000) != 0;
        return ctrl && alt;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _events.Writer.TryComplete();

        if (_marshalingControl is not null && _appContext is not null)
        {
            try
            {
                _marshalingControl.Invoke(() =>
                {
                    if (_mouseHook != IntPtr.Zero)
                    {
                        Win32Interop.UnhookWindowsHookEx(_mouseHook);
                        _mouseHook = IntPtr.Zero;
                    }
                    if (_keyboardHook != IntPtr.Zero)
                    {
                        Win32Interop.UnhookWindowsHookEx(_keyboardHook);
                        _keyboardHook = IntPtr.Zero;
                    }
                    _overlay?.HideOverlay();
                    _overlay?.Dispose();
                    _rawWindow?.DestroyHandle();
                    _marshalingControl.Dispose();
                    _appContext.ExitThread();
                });
            }
            catch
            {
                // Best-effort teardown on shutdown
            }
        }

        _hookThread?.Join(1000);
    }

    private sealed class RawInputWindow : NativeWindow
    {
        private readonly Action<Win32Interop.RAWMOUSE> _onMouse;

        public RawInputWindow(Action<Win32Interop.RAWMOUSE> onMouse)
        {
            _onMouse = onMouse;

            CreateHandle(new CreateParams
            {
                Caption = "LanKvmRawInputSink",
                Parent = Win32Interop.HWND_MESSAGE
            });

            var devices = new[]
            {
                new Win32Interop.RAWINPUTDEVICE
                {
                    usUsagePage = Win32Interop.HID_USAGE_PAGE_GENERIC,
                    usUsage = Win32Interop.HID_USAGE_GENERIC_MOUSE,
                    dwFlags = Win32Interop.RIDEV_INPUTSINK,
                    hwndTarget = Handle
                }
            };

            if (!Win32Interop.RegisterRawInputDevices(devices, (uint)devices.Length, (uint)Marshal.SizeOf<Win32Interop.RAWINPUTDEVICE>()))
            {
                throw new InvalidOperationException($"RegisterRawInputDevices failed ({Marshal.GetLastWin32Error()}).");
            }
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == Win32Interop.WM_INPUT)
            {
                ProcessRawInput(m.LParam);
            }
            base.WndProc(ref m);
        }

        private void ProcessRawInput(IntPtr hRawInput)
        {
            uint size = 0;
            uint headerSize = (uint)Marshal.SizeOf<Win32Interop.RAWINPUTHEADER>();
            if (Win32Interop.GetRawInputData(hRawInput, Win32Interop.RID_INPUT, IntPtr.Zero, ref size, headerSize) != 0 || size == 0)
                return;

            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                if (Win32Interop.GetRawInputData(hRawInput, Win32Interop.RID_INPUT, buffer, ref size, headerSize) != size)
                    return;

                var header = Marshal.PtrToStructure<Win32Interop.RAWINPUTHEADER>(buffer);
                if (header.dwType == Win32Interop.RIM_TYPEMOUSE)
                {
                    var mouse = Marshal.PtrToStructure<Win32Interop.RAWMOUSE>(IntPtr.Add(buffer, (int)headerSize));
                    _onMouse(mouse);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
