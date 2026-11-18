using System.Diagnostics;
using System.Runtime.InteropServices;
using LanKvm.Core.Native;
using LanKvm.Protocol;
using Microsoft.Win32;

namespace LanKvm.Core.Input;

/// <summary>
/// Injects remote mouse and keyboard events into the Client OS via Win32 SendInput
/// with cached bounds and reusable input buffers, and detects return-edge pushes.
/// </summary>
public sealed class ClientInputInjector : IDisposable
{
    private static readonly int InputSize = Marshal.SizeOf<Win32Interop.INPUT>();

    private readonly SubPixelAccumulator _subPixel = new();
    private readonly EdgeSwitchStateMachine _returnState;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly object _keysLock = new();
    private readonly object _sendLock = new();
    private readonly Win32Interop.INPUT[] _singleInput = new Win32Interop.INPUT[1];
    private readonly HashSet<(ushort Vk, ushort Scan, bool Ext)> _pressedKeys = new();

    private ScreenRect _cachedBounds;
    private volatile bool _isControlledByHost;
    private volatile ScreenEdge _hostSwitchEdge = ScreenEdge.Right;
    private double _sensitivity = 1.0;
    private bool _disposed;

    public event Action<ScreenEdge, float>? ReturnToHostRequested;

    public ClientInputInjector(int returnResistancePixels = 16, long cooldownMs = 150)
    {
        _returnState = new EdgeSwitchStateMachine(returnResistancePixels, cooldownMs);
        RefreshBounds();
        SystemEvents.DisplaySettingsChanged += OnDisplaySettingsChanged;
    }

    public double Sensitivity
    {
        get => _sensitivity;
        set => _sensitivity = Math.Clamp(value, 0.2, 3.0);
    }

    public bool IsControlledByHost => _isControlledByHost;

    private void OnDisplaySettingsChanged(object? sender, EventArgs e) => RefreshBounds();

    private void RefreshBounds()
    {
        var (vLeft, vTop, vWidth, vHeight) = Win32Interop.GetVirtualScreenBounds();
        _cachedBounds = new ScreenRect(vLeft, vTop, vWidth, vHeight);
    }

    public void ActivateFromHost(ScreenEdge hostSwitchEdge, float ratio)
    {
        _hostSwitchEdge = hostSwitchEdge;
        _subPixel.Reset();
        _returnState.ResetToLocal(_clock.ElapsedMilliseconds);
        _isControlledByHost = true;

        RefreshBounds();
        ScreenEdge entryEdge = EdgeSwitchStateMachine.OppositeEdge(hostSwitchEdge);
        var (x, y) = EdgeSwitchStateMachine.ComputeEntryPoint(_cachedBounds, entryEdge, ratio, insetPx: 8);
        Win32Interop.SetCursorPos(x, y);
    }

    public void DeactivateAndReleaseAll()
    {
        _isControlledByHost = false;
        _subPixel.Reset();
        ReleaseAllPressedKeys();
    }

    public void InjectMouseDelta(int rawDx, int rawDy)
    {
        var (dx, dy) = _subPixel.Scale(rawDx, rawDy, _sensitivity);
        if (dx == 0 && dy == 0) return;

        SendSingleInput(new Win32Interop.INPUT
        {
            type = Win32Interop.INPUT_MOUSE,
            u = new Win32Interop.INPUTUNION
            {
                mi = new Win32Interop.MOUSEINPUT
                {
                    dx = dx,
                    dy = dy,
                    mouseData = 0,
                    dwFlags = Win32Interop.MOUSEEVENTF_MOVE,
                    time = 0,
                    dwExtraInfo = Win32Interop.SyntheticExtraInfo
                }
            }
        });

        if (_isControlledByHost && Win32Interop.GetCursorPos(out var pt))
        {
            if (_returnState.TryShouldReturnToHost(
                    pt.X, pt.Y, dx, dy, _cachedBounds, _hostSwitchEdge, _clock.ElapsedMilliseconds, out float ratio))
            {
                _isControlledByHost = false;
                ReleaseAllPressedKeys();
                ReturnToHostRequested?.Invoke(_hostSwitchEdge, ratio);
            }
        }
    }

    public void InjectMouseButton(MouseButtonPayload p)
    {
        uint flag;
        uint mouseData = 0;

        switch (p.Button)
        {
            case MouseButtonKind.Left:
                flag = p.IsDown ? Win32Interop.MOUSEEVENTF_LEFTDOWN : Win32Interop.MOUSEEVENTF_LEFTUP;
                break;
            case MouseButtonKind.Right:
                flag = p.IsDown ? Win32Interop.MOUSEEVENTF_RIGHTDOWN : Win32Interop.MOUSEEVENTF_RIGHTUP;
                break;
            case MouseButtonKind.Middle:
                flag = p.IsDown ? Win32Interop.MOUSEEVENTF_MIDDLEDOWN : Win32Interop.MOUSEEVENTF_MIDDLEUP;
                break;
            case MouseButtonKind.XButton1:
                flag = p.IsDown ? Win32Interop.MOUSEEVENTF_XDOWN : Win32Interop.MOUSEEVENTF_XUP;
                mouseData = 1;
                break;
            case MouseButtonKind.XButton2:
                flag = p.IsDown ? Win32Interop.MOUSEEVENTF_XDOWN : Win32Interop.MOUSEEVENTF_XUP;
                mouseData = 2;
                break;
            default:
                return;
        }

        SendSingleInput(new Win32Interop.INPUT
        {
            type = Win32Interop.INPUT_MOUSE,
            u = new Win32Interop.INPUTUNION
            {
                mi = new Win32Interop.MOUSEINPUT
                {
                    dx = 0,
                    dy = 0,
                    mouseData = mouseData,
                    dwFlags = flag,
                    time = 0,
                    dwExtraInfo = Win32Interop.SyntheticExtraInfo
                }
            }
        });
    }

    public void InjectMouseWheel(MouseWheelPayload p)
    {
        SendSingleInput(new Win32Interop.INPUT
        {
            type = Win32Interop.INPUT_MOUSE,
            u = new Win32Interop.INPUTUNION
            {
                mi = new Win32Interop.MOUSEINPUT
                {
                    dx = 0,
                    dy = 0,
                    mouseData = unchecked((uint)p.Delta),
                    dwFlags = p.IsHorizontal ? Win32Interop.MOUSEEVENTF_HWHEEL : Win32Interop.MOUSEEVENTF_WHEEL,
                    time = 0,
                    dwExtraInfo = Win32Interop.SyntheticExtraInfo
                }
            }
        });
    }

    public void InjectKeyEvent(KeyEventPayload p)
    {
        lock (_keysLock)
        {
            var tuple = (p.VirtualKey, p.ScanCode, p.IsExtended);
            if (p.IsKeyUp)
            {
                _pressedKeys.Remove(tuple);
            }
            else
            {
                _pressedKeys.Add(tuple);
            }
        }

        SendKeyInput(p.VirtualKey, p.ScanCode, p.IsExtended, p.IsKeyUp);
    }

    public void ReleaseAllPressedKeys()
    {
        List<(ushort Vk, ushort Scan, bool Ext)> snapshot;
        lock (_keysLock)
        {
            if (_pressedKeys.Count == 0) return;
            snapshot = _pressedKeys.ToList();
            _pressedKeys.Clear();
        }

        foreach (var (vk, scan, ext) in snapshot)
        {
            SendKeyInput(vk, scan, ext, isKeyUp: true);
        }
    }

    private void SendKeyInput(ushort vk, ushort scan, bool isExtended, bool isKeyUp)
    {
        bool useVirtualKeyOnly =
            vk == Win32Interop.VK_HANGUL ||
            vk == Win32Interop.VK_HANJA ||
            scan == 0;

        uint flags = 0;
        if (!useVirtualKeyOnly)
        {
            flags |= Win32Interop.KEYEVENTF_SCANCODE;
        }
        if (isExtended && !useVirtualKeyOnly)
        {
            flags |= Win32Interop.KEYEVENTF_EXTENDEDKEY;
        }
        if (isKeyUp)
        {
            flags |= Win32Interop.KEYEVENTF_KEYUP;
        }

        SendSingleInput(new Win32Interop.INPUT
        {
            type = Win32Interop.INPUT_KEYBOARD,
            u = new Win32Interop.INPUTUNION
            {
                ki = new Win32Interop.KEYBDINPUT
                {
                    wVk = useVirtualKeyOnly ? vk : (ushort)0,
                    wScan = useVirtualKeyOnly ? (ushort)0 : scan,
                    dwFlags = flags,
                    time = 0,
                    dwExtraInfo = Win32Interop.SyntheticExtraInfo
                }
            }
        });
    }

    private void SendSingleInput(Win32Interop.INPUT input)
    {
        lock (_sendLock)
        {
            _singleInput[0] = input;
            Win32Interop.SendInput(1, _singleInput, InputSize);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        SystemEvents.DisplaySettingsChanged -= OnDisplaySettingsChanged;
        ReleaseAllPressedKeys();
    }
}
