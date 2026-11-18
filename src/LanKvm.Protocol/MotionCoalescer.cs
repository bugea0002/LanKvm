namespace LanKvm.Protocol;

/// <summary>
/// Thread-safe lock-free accumulator that merges high-frequency mouse deltas
/// and wakes the sender only when movement actually occurs (0% idle CPU).
/// </summary>
public sealed class MotionCoalescer : IDisposable
{
    private readonly SemaphoreSlim _signal = new(0, 1);
    private int _dx;
    private int _dy;

    public void AddDelta(int dx, int dy)
    {
        if (dx == 0 && dy == 0) return;
        if (dx != 0) Interlocked.Add(ref _dx, dx);
        if (dy != 0) Interlocked.Add(ref _dy, dy);

        if (_signal.CurrentCount == 0)
        {
            try { _signal.Release(); } catch (SemaphoreFullException) { }
        }
    }

    public ValueTask WaitForDataAsync(CancellationToken cancellationToken) =>
        new(_signal.WaitAsync(cancellationToken));

    public bool TryDrain(out int dx, out int dy)
    {
        dx = Interlocked.Exchange(ref _dx, 0);
        dy = Interlocked.Exchange(ref _dy, 0);
        return dx != 0 || dy != 0;
    }

    public void Reset()
    {
        Interlocked.Exchange(ref _dx, 0);
        Interlocked.Exchange(ref _dy, 0);
    }

    public void Dispose() => _signal.Dispose();
}

/// <summary>
/// Preserves fractional cursor movement when sensitivity scaling is applied
/// so slow mouse movement never rounds down to zero.
/// </summary>
public sealed class SubPixelAccumulator
{
    private decimal _remX;
    private decimal _remY;

    public (int Dx, int Dy) Scale(int rawDx, int rawDy, double sensitivity)
    {
        decimal factor = (decimal)Math.Round(sensitivity, 4);
        decimal totalX = rawDx * factor + _remX;
        decimal totalY = rawDy * factor + _remY;

        int outX = (int)decimal.Truncate(totalX);
        int outY = (int)decimal.Truncate(totalY);

        _remX = totalX - outX;
        _remY = totalY - outY;

        return (outX, outY);
    }

    public void Reset()
    {
        _remX = 0m;
        _remY = 0m;
    }
}
