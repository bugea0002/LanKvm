using LanKvm.Protocol;

namespace LanKvm.Core.Input;

public readonly record struct ScreenRect(int Left, int Top, int Width, int Height)
{
    public int Right => Left + Width - 1;
    public int Bottom => Top + Height - 1;
}

/// <summary>
/// Pure state machine governing screen-edge transitions with edge resistance
/// and post-switch cooldown to prevent accidental corner bouncing.
/// </summary>
public sealed class EdgeSwitchStateMachine
{
    private readonly int _resistancePixels;
    private readonly long _cooldownMs;

    private int _pushAccum;
    private long _lastSwitchTickMs;

    public bool IsRemote { get; private set; }

    public EdgeSwitchStateMachine(int resistancePixels = 16, long cooldownMs = 150)
    {
        _resistancePixels = Math.Max(0, resistancePixels);
        _cooldownMs = Math.Max(0, cooldownMs);
        _lastSwitchTickMs = -cooldownMs;
    }

    public void ResetToLocal(long nowMs)
    {
        IsRemote = false;
        _pushAccum = 0;
        _lastSwitchTickMs = nowMs;
    }

    public void EnterRemote(long nowMs)
    {
        IsRemote = true;
        _pushAccum = 0;
        _lastSwitchTickMs = nowMs;
    }

    /// <summary>
    /// Host side: checks whether cursor at (cursorX, cursorY) pushed past the configured switch edge.
    /// </summary>
    public bool TryShouldSwitchToClient(
        int cursorX,
        int cursorY,
        int rawDx,
        int rawDy,
        ScreenRect hostBounds,
        ScreenEdge switchEdge,
        long nowMs,
        out float ratio)
    {
        ratio = 0.5f;
        if (IsRemote) return false;
        if (nowMs - _lastSwitchTickMs < _cooldownMs) return false;

        int pushDelta;
        bool onEdge;
        switch (switchEdge)
        {
            case ScreenEdge.Right:
                onEdge = cursorX >= hostBounds.Right;
                pushDelta = rawDx;
                ratio = NormalizeRatio(cursorY, hostBounds.Top, hostBounds.Height);
                break;
            case ScreenEdge.Left:
                onEdge = cursorX <= hostBounds.Left;
                pushDelta = -rawDx;
                ratio = NormalizeRatio(cursorY, hostBounds.Top, hostBounds.Height);
                break;
            case ScreenEdge.Bottom:
                onEdge = cursorY >= hostBounds.Bottom;
                pushDelta = rawDy;
                ratio = NormalizeRatio(cursorX, hostBounds.Left, hostBounds.Width);
                break;
            case ScreenEdge.Top:
                onEdge = cursorY <= hostBounds.Top;
                pushDelta = -rawDy;
                ratio = NormalizeRatio(cursorX, hostBounds.Left, hostBounds.Width);
                break;
            default:
                return false;
        }

        if (!onEdge)
        {
            _pushAccum = 0;
            return false;
        }

        if (pushDelta > 0)
        {
            _pushAccum += pushDelta;
        }
        else if (pushDelta < 0)
        {
            _pushAccum = 0;
        }

        if (_pushAccum >= _resistancePixels)
        {
            EnterRemote(nowMs);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Client side: checks whether cursor pushed past the entry edge back toward the host.
    /// </summary>
    public bool TryShouldReturnToHost(
        int cursorX,
        int cursorY,
        int injectedDx,
        int injectedDy,
        ScreenRect clientBounds,
        ScreenEdge hostSwitchEdge,
        long nowMs,
        out float ratio)
    {
        ratio = 0.5f;
        if (nowMs - _lastSwitchTickMs < _cooldownMs) return false;

        // If host switches on Right, client enters on Left and returns via Left.
        ScreenEdge clientReturnEdge = OppositeEdge(hostSwitchEdge);

        int pushDelta;
        bool onEdge;
        switch (clientReturnEdge)
        {
            case ScreenEdge.Left:
                onEdge = cursorX <= clientBounds.Left;
                pushDelta = -injectedDx;
                ratio = NormalizeRatio(cursorY, clientBounds.Top, clientBounds.Height);
                break;
            case ScreenEdge.Right:
                onEdge = cursorX >= clientBounds.Right;
                pushDelta = injectedDx;
                ratio = NormalizeRatio(cursorY, clientBounds.Top, clientBounds.Height);
                break;
            case ScreenEdge.Top:
                onEdge = cursorY <= clientBounds.Top;
                pushDelta = -injectedDy;
                ratio = NormalizeRatio(cursorX, clientBounds.Left, clientBounds.Width);
                break;
            case ScreenEdge.Bottom:
                onEdge = cursorY >= clientBounds.Bottom;
                pushDelta = injectedDy;
                ratio = NormalizeRatio(cursorX, clientBounds.Left, clientBounds.Width);
                break;
            default:
                return false;
        }

        if (!onEdge)
        {
            _pushAccum = 0;
            return false;
        }

        if (pushDelta > 0)
        {
            _pushAccum += pushDelta;
        }
        else if (pushDelta < 0)
        {
            _pushAccum = 0;
        }

        if (_pushAccum >= _resistancePixels)
        {
            _pushAccum = 0;
            _lastSwitchTickMs = nowMs;
            return true;
        }

        return false;
    }

    public static ScreenEdge OppositeEdge(ScreenEdge edge) => edge switch
    {
        ScreenEdge.Right => ScreenEdge.Left,
        ScreenEdge.Left => ScreenEdge.Right,
        ScreenEdge.Top => ScreenEdge.Bottom,
        ScreenEdge.Bottom => ScreenEdge.Top,
        _ => ScreenEdge.Left
    };

    public static (int X, int Y) ComputeEntryPoint(ScreenRect bounds, ScreenEdge enterFromSideOfScreen, float ratio, int insetPx = 6)
    {
        float clamped = Math.Clamp(ratio, 0f, 1f);
        int safeInsetX = Math.Min(insetPx, Math.Max(0, bounds.Width / 4));
        int safeInsetY = Math.Min(insetPx, Math.Max(0, bounds.Height / 4));

        return enterFromSideOfScreen switch
        {
            ScreenEdge.Left => (bounds.Left + safeInsetX, bounds.Top + (int)Math.Round(clamped * Math.Max(1, bounds.Height - 1))),
            ScreenEdge.Right => (bounds.Right - safeInsetX, bounds.Top + (int)Math.Round(clamped * Math.Max(1, bounds.Height - 1))),
            ScreenEdge.Top => (bounds.Left + (int)Math.Round(clamped * Math.Max(1, bounds.Width - 1)), bounds.Top + safeInsetY),
            ScreenEdge.Bottom => (bounds.Left + (int)Math.Round(clamped * Math.Max(1, bounds.Width - 1)), bounds.Bottom - safeInsetY),
            _ => (bounds.Left + bounds.Width / 2, bounds.Top + bounds.Height / 2)
        };
    }

    private static float NormalizeRatio(int pos, int start, int length)
    {
        if (length <= 1) return 0.5f;
        return Math.Clamp((pos - start) / (float)(length - 1), 0f, 1f);
    }
}
