using System.Diagnostics;

namespace LanKvm.Core.Native;

/// <summary>
/// Prevents multiple active UI instances of LanKvm from flapping host/client connections,
/// and notifies the already-running instance to bring its window to the foreground.
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
    private const string WaitPidArg = "--wait-pid";
    private const string CleanupUpdateArg = "--cleanup-update";

    private readonly Mutex? _mutex;
    private readonly EventWaitHandle? _showEvent;
    private RegisteredWaitHandle? _waitRegistration;
    private bool _ownsMutex;
    private bool _disposed;

    private SingleInstanceGuard(Mutex mutex, EventWaitHandle showEvent, bool ownsMutex)
    {
        _mutex = mutex;
        _showEvent = showEvent;
        _ownsMutex = ownsMutex;
    }

    public static bool TryParseWaitPid(string[] args, out int pid)
    {
        pid = 0;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], WaitPidArg, StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(args[i + 1], out int parsed) &&
                parsed > 0)
            {
                pid = parsed;
                return true;
            }
        }
        return false;
    }

    public static bool HasCleanupUpdateArg(string[] args) =>
        args.Any(a => string.Equals(a, CleanupUpdateArg, StringComparison.OrdinalIgnoreCase));

    public static bool TryAcquire(
        string mutexName,
        string showEventName,
        string[] args,
        bool notifyExistingIfDuplicate,
        Action? fallbackCrossPrivilegeNotify,
        out SingleInstanceGuard? guard)
    {
        guard = null;

        if (TryParseWaitPid(args, out int previousPid))
        {
            WaitForProcessExit(previousPid, 8000);
        }

        // During elevation restart or post-update cleanup, allow brief grace for the exiting process
        // to close its kernel handles before declaring a duplicate launch.
        bool allowWaitRetry = previousPid > 0 || HasCleanupUpdateArg(args);
        int maxWaitMs = allowWaitRetry ? 3500 : 0;

        Mutex? mutex = null;
        bool acquired = false;
        try
        {
            mutex = new Mutex(initiallyOwned: false, name: mutexName);
            int elapsed = 0;
            while (true)
            {
                try
                {
                    acquired = mutex.WaitOne(0, exitContext: false);
                }
                catch (AbandonedMutexException)
                {
                    acquired = true;
                }

                if (acquired || elapsed >= maxWaitMs)
                {
                    break;
                }

                Thread.Sleep(100);
                elapsed += 100;
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Another instance running at higher privilege owns the mutex in this session.
            mutex?.Dispose();
            mutex = null;
            acquired = false;
        }

        if (!acquired)
        {
            mutex?.Dispose();
            if (notifyExistingIfDuplicate)
            {
                SignalExistingInstance(showEventName, fallbackCrossPrivilegeNotify);
            }
            return false;
        }

        EventWaitHandle showEvent;
        try
        {
            showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, showEventName);
        }
        catch (UnauthorizedAccessException)
        {
            showEvent = new EventWaitHandle(false, EventResetMode.AutoReset);
        }

        guard = new SingleInstanceGuard(mutex!, showEvent, ownsMutex: true);
        return true;
    }

    public void RegisterActivationCallback(Action onActivate)
    {
        if (_disposed || _showEvent is null) return;

        _waitRegistration?.Unregister(null);
        _waitRegistration = ThreadPool.RegisterWaitForSingleObject(
            _showEvent,
            (_, timedOut) =>
            {
                if (!timedOut && !_disposed)
                {
                    onActivate();
                }
            },
            state: null,
            millisecondsTimeOutInterval: Timeout.Infinite,
            executeOnlyOnce: false);
    }

    public static void SignalExistingInstance(string showEventName, Action? fallbackCrossPrivilegeNotify)
    {
        try
        {
            if (EventWaitHandle.TryOpenExisting(showEventName, out EventWaitHandle? existing))
            {
                using (existing)
                {
                    existing.Set();
                    return;
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Expected when existing instance runs elevated and current instance runs standard user.
        }
        catch
        {
            // Ignore and fall back.
        }

        fallbackCrossPrivilegeNotify?.Invoke();
    }

    private static void WaitForProcessExit(int pid, int timeoutMs)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (!proc.HasExited)
            {
                proc.WaitForExit(timeoutMs);
            }
        }
        catch
        {
            // Process already exited.
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _waitRegistration?.Unregister(null);
        _waitRegistration = null;
        _showEvent?.Dispose();

        if (_mutex is not null)
        {
            if (_ownsMutex)
            {
                try { _mutex.ReleaseMutex(); } catch { }
                _ownsMutex = false;
            }
            _mutex.Dispose();
        }
    }
}
