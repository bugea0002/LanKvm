using System.Collections.Specialized;
using System.Drawing;
using System.Drawing.Imaging;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using LanKvm.Core.Native;

namespace LanKvm.Core.Clipboard;

public enum ClipboardContentKind
{
    Text = 0,
    Image = 1,
    FileDrop = 2
}

public sealed record ClipboardPayload(
    ClipboardContentKind Kind,
    byte[] Data,
    IReadOnlyList<string>? FilePaths = null)
{
    public bool IsImage => Kind == ClipboardContentKind.Image;
}

/// <summary>
/// Pure helper for deduplicating clipboard contents via SHA-256 so remote updates
/// written locally never bounce back as new outgoing sync events.
/// </summary>
public sealed class ClipboardDeduplicator
{
    private readonly object _gate = new();
    private byte[]? _lastAppliedHash;

    public void MarkRemoteApplied(ReadOnlySpan<byte> payload)
    {
        byte[] hash = SHA256.HashData(payload);
        lock (_gate)
        {
            _lastAppliedHash = hash;
        }
    }

    public bool ShouldSkipOutgoing(ReadOnlySpan<byte> payload)
    {
        byte[] hash = SHA256.HashData(payload);
        lock (_gate)
        {
            if (_lastAppliedHash is not null &&
                CryptographicOperations.FixedTimeEquals(_lastAppliedHash, hash))
            {
                return true;
            }

            _lastAppliedHash = hash;
            return false;
        }
    }

    public void Reset()
    {
        lock (_gate)
        {
            _lastAppliedHash = null;
        }
    }
}

/// <summary>
/// Monitors Windows clipboard updates on a dedicated STA thread, debounces bursts
/// (e.g. Win+Shift+S), retries transient OpenClipboard locks, and syncs Text, PNG Images, and File Drops.
/// </summary>
public sealed class ClipboardSyncService : IDisposable
{
    public const int MaxTextBytes = 10 * 1024 * 1024;
    public const int MaxImageBytes = 20 * 1024 * 1024;

    private readonly ClipboardDeduplicator _dedup = new();
    private readonly Func<ClipboardPayload, Task> _onLocalClipboardChanged;

    private Thread? _staThread;
    private ApplicationContext? _appContext;
    private ClipboardListenerWindow? _window;
    private Control? _marshalingControl;
    private CancellationTokenSource? _debounceCts;
    private uint _lastSeq;
    private volatile bool _enabled = true;
    private volatile bool _disposed;

    public ClipboardSyncService(Func<ClipboardPayload, Task> onLocalClipboardChanged)
    {
        _onLocalClipboardChanged = onLocalClipboardChanged;
    }

    public bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    public void Start()
    {
        if (_staThread is not null) return;

        using var ready = new ManualResetEventSlim(false);
        Exception? initError = null;

        _staThread = new Thread(() =>
        {
            try
            {
                _appContext = new ApplicationContext();
                _marshalingControl = new Control();
                _ = _marshalingControl.Handle;
                _window = new ClipboardListenerWindow(OnClipboardChangedMessage);
                _lastSeq = Win32Interop.GetClipboardSequenceNumber();
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
            Name = "LanKvm-ClipboardThread",
            IsBackground = true
        };
        _staThread.SetApartmentState(ApartmentState.STA);
        _staThread.Start();
        ready.Wait();

        if (initError is not null)
        {
            throw new InvalidOperationException("Failed to initialize ClipboardSyncService.", initError);
        }
    }

    public void ApplyRemoteClipboard(ClipboardPayload payload)
    {
        if (!_enabled || _disposed || _marshalingControl is null) return;

        _marshalingControl.BeginInvoke(() =>
        {
            if (payload.Kind == ClipboardContentKind.FileDrop && payload.FilePaths is { Count: > 0 })
            {
                byte[] sig = ComputeFileDropSignature(payload.FilePaths);
                _dedup.MarkRemoteApplied(sig);
                RunWithClipboardRetry(() =>
                {
                    var col = new StringCollection();
                    foreach (string p in payload.FilePaths) col.Add(p);
                    System.Windows.Forms.Clipboard.SetFileDropList(col);
                });
            }
            else
            {
                _dedup.MarkRemoteApplied(payload.Data);
                RunWithClipboardRetry(() =>
                {
                    if (payload.IsImage)
                    {
                        using var ms = new MemoryStream(payload.Data);
                        using var img = Image.FromStream(ms);
                        using var bmp = new Bitmap(img);
                        System.Windows.Forms.Clipboard.SetImage(bmp);
                    }
                    else
                    {
                        string text = Encoding.UTF8.GetString(payload.Data);
                        if (!string.IsNullOrEmpty(text))
                        {
                            System.Windows.Forms.Clipboard.SetText(text, TextDataFormat.UnicodeText);
                        }
                    }
                });
            }
            _lastSeq = Win32Interop.GetClipboardSequenceNumber();
        });
    }

    private void OnClipboardChangedMessage()
    {
        if (!_enabled || _disposed) return;

        uint seq = Win32Interop.GetClipboardSequenceNumber();
        if (seq == _lastSeq) return;
        _lastSeq = seq;

        _debounceCts?.Cancel();
        _debounceCts?.Dispose();
        var cts = new CancellationTokenSource();
        _debounceCts = cts;

        _ = DebouncedReadAndSendAsync(cts.Token);
    }

    private async Task DebouncedReadAndSendAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(90, ct).ConfigureAwait(false);
            if (ct.IsCancellationRequested || _disposed || !_enabled || _marshalingControl is null) return;

            var tcs = new TaskCompletionSource<ClipboardPayload?>();
            _marshalingControl.BeginInvoke(() =>
            {
                try
                {
                    tcs.TrySetResult(ReadCurrentClipboardWithRetry());
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            });

            ClipboardPayload? payload = await tcs.Task.ConfigureAwait(false);
            if (payload is null || ct.IsCancellationRequested) return;
            if (_dedup.ShouldSkipOutgoing(payload.Data)) return;

            await _onLocalClipboardChanged(payload).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Debounced by a newer clipboard event
        }
        catch
        {
            // Ignore transient clipboard read errors
        }
    }

    private static ClipboardPayload? ReadCurrentClipboardWithRetry()
    {
        ClipboardPayload? result = null;
        RunWithClipboardRetry(() =>
        {
            if (System.Windows.Forms.Clipboard.ContainsFileDropList())
            {
                StringCollection list = System.Windows.Forms.Clipboard.GetFileDropList();
                if (list.Count > 0)
                {
                    var paths = new List<string>(list.Count);
                    foreach (string? p in list)
                    {
                        if (!string.IsNullOrWhiteSpace(p)) paths.Add(p);
                    }
                    if (paths.Count > 0)
                    {
                        result = new ClipboardPayload(
                            ClipboardContentKind.FileDrop,
                            ComputeFileDropSignature(paths),
                            paths);
                        return;
                    }
                }
            }

            if (System.Windows.Forms.Clipboard.ContainsImage())
            {
                using Image? img = System.Windows.Forms.Clipboard.GetImage();
                if (img is not null)
                {
                    using var ms = new MemoryStream();
                    img.Save(ms, ImageFormat.Png);
                    if (ms.Length > 0 && ms.Length <= MaxImageBytes)
                    {
                        result = new ClipboardPayload(ClipboardContentKind.Image, ms.ToArray());
                        return;
                    }
                }
            }

            if (System.Windows.Forms.Clipboard.ContainsText(TextDataFormat.UnicodeText))
            {
                string text = System.Windows.Forms.Clipboard.GetText(TextDataFormat.UnicodeText);
                if (!string.IsNullOrEmpty(text))
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(text);
                    if (bytes.Length <= MaxTextBytes)
                    {
                        result = new ClipboardPayload(ClipboardContentKind.Text, bytes);
                    }
                }
            }
        });

        return result;
    }

    private static byte[] ComputeFileDropSignature(IReadOnlyList<string> paths)
    {
        string joined = string.Join("\n", paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase));
        return Encoding.UTF8.GetBytes(joined);
    }

    private static void RunWithClipboardRetry(Action action)
    {
        const int maxAttempts = 8;
        for (int i = 0; i < maxAttempts; i++)
        {
            try
            {
                action();
                return;
            }
            catch (Exception ex) when (i < maxAttempts - 1 &&
                                       (ex is System.Runtime.InteropServices.ExternalException ||
                                        ex is UnauthorizedAccessException))
            {
                Thread.Sleep(25);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _debounceCts?.Cancel();
        _debounceCts?.Dispose();

        if (_marshalingControl is not null && _appContext is not null)
        {
            try
            {
                _marshalingControl.Invoke(() =>
                {
                    _window?.DestroyHandle();
                    _marshalingControl.Dispose();
                    _appContext.ExitThread();
                });
            }
            catch
            {
                // Best-effort teardown
            }
        }

        _staThread?.Join(1000);
    }

    private sealed class ClipboardListenerWindow : NativeWindow
    {
        private readonly Action _onClipboardUpdate;

        public ClipboardListenerWindow(Action onClipboardUpdate)
        {
            _onClipboardUpdate = onClipboardUpdate;
            CreateHandle(new CreateParams
            {
                Caption = "LanKvmClipboardListener",
                Parent = Win32Interop.HWND_MESSAGE
            });

            if (!Win32Interop.AddClipboardFormatListener(Handle))
            {
                throw new InvalidOperationException("AddClipboardFormatListener failed.");
            }
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == Win32Interop.WM_CLIPBOARDUPDATE)
            {
                _onClipboardUpdate();
            }
            base.WndProc(ref m);
        }

        public override void DestroyHandle()
        {
            if (Handle != IntPtr.Zero)
            {
                Win32Interop.RemoveClipboardFormatListener(Handle);
            }
            base.DestroyHandle();
        }
    }
}
