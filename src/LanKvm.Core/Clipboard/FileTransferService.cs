using System.Security.Cryptography;
using LanKvm.Protocol;

namespace LanKvm.Core.Clipboard;

public sealed record PreparedFileTransfer(
    FileOfferPayload Offer,
    IReadOnlyList<string> SourceFilePaths);

/// <summary>
/// Builds safe file transfer manifests from Windows clipboard file drops,
/// enforces strict path traversal and size/count limits, and reassembles
/// verified files into %LocalAppData%\LanKvm\Inbox.
/// </summary>
public static class FileTransferService
{
    public const int MaxFiles = 200;
    public const long MaxTotalBytes = 1024L * 1024 * 1024; // 1 GB
    public const int ChunkSizeBytes = 256 * 1024;

    public static string InboxRootDir => Path.Combine(ConfigStore.LocalDataDir, "Inbox");

    public static bool TryBuildTransfer(
        IReadOnlyList<string> sourcePaths,
        out PreparedFileTransfer? prepared,
        out string? errorReason)
    {
        prepared = null;
        errorReason = null;

        if (sourcePaths.Count == 0)
        {
            errorReason = "복사된 파일이 없습니다.";
            return false;
        }

        var topLevels = new List<string>();
        var usedTopNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<FileEntryInfo>();
        var fullSourceFiles = new List<string>();
        long totalBytes = 0;

        foreach (string rawPath in sourcePaths)
        {
            if (string.IsNullOrWhiteSpace(rawPath)) continue;

            if (File.Exists(rawPath))
            {
                var fi = new FileInfo(rawPath);
                if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;

                string name = EnsureUniqueTopName(fi.Name, usedTopNames);
                if (entries.Count >= MaxFiles)
                {
                    errorReason = $"최대 {MaxFiles}개 파일까지만 전송할 수 있습니다.";
                    return false;
                }
                totalBytes += fi.Length;
                if (totalBytes > MaxTotalBytes)
                {
                    errorReason = "총 파일 크기가 1GB 한도를 초과합니다.";
                    return false;
                }

                topLevels.Add(name);
                entries.Add(new FileEntryInfo(name, fi.Length));
                fullSourceFiles.Add(fi.FullName);
            }
            else if (Directory.Exists(rawPath))
            {
                var di = new DirectoryInfo(rawPath);
                if (di.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;

                string topName = EnsureUniqueTopName(di.Name, usedTopNames);
                topLevels.Add(topName);

                var enumOpts = new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System
                };

                foreach (FileInfo fi in di.EnumerateFiles("*", enumOpts))
                {
                    if (entries.Count >= MaxFiles)
                    {
                        errorReason = $"최대 {MaxFiles}개 파일까지만 전송할 수 있습니다.";
                        return false;
                    }
                    totalBytes += fi.Length;
                    if (totalBytes > MaxTotalBytes)
                    {
                        errorReason = "총 파일 크기가 1GB 한도를 초과합니다.";
                        return false;
                    }

                    string relInside = Path.GetRelativePath(di.FullName, fi.FullName).Replace('\\', '/');
                    entries.Add(new FileEntryInfo($"{topName}/{relInside}", fi.Length));
                    fullSourceFiles.Add(fi.FullName);
                }
            }
        }

        if (topLevels.Count == 0)
        {
            errorReason = "전송 가능한 파일이 없습니다.";
            return false;
        }

        ulong id = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        prepared = new PreparedFileTransfer(new FileOfferPayload(id, topLevels, entries), fullSourceFiles);
        return true;
    }

    public static string ResolveSafeDestinationPath(string rootDir, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new InvalidDataException("Empty relative file path.");
        if (relativePath.Contains(':') || relativePath.StartsWith('\\') || relativePath.StartsWith('/'))
            throw new InvalidDataException($"Absolute or drive path rejected: {relativePath}");
        if (Path.IsPathRooted(relativePath))
            throw new InvalidDataException($"Rooted path rejected: {relativePath}");

        string normalizedRel = relativePath.Replace('/', Path.DirectorySeparatorChar);
        string[] segments = normalizedRel.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(s => s is "." or ".."))
            throw new InvalidDataException($"Path traversal segment rejected: {relativePath}");

        string fullRoot = Path.GetFullPath(rootDir);
        string rootWithSep = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;

        string candidate = Path.GetFullPath(Path.Combine(fullRoot, Path.Combine(segments)));
        if (!candidate.StartsWith(rootWithSep, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Path escaped sandbox: {relativePath}");

        return candidate;
    }

    public static void CleanupOldInboxFolders(int keepLatest = 3)
    {
        try
        {
            if (!Directory.Exists(InboxRootDir)) return;

            var dirs = new DirectoryInfo(InboxRootDir)
                .GetDirectories()
                .OrderByDescending(d => d.CreationTimeUtc)
                .ToList();

            for (int i = keepLatest; i < dirs.Count; i++)
            {
                try { dirs[i].Delete(recursive: true); } catch { }
            }
        }
        catch
        {
            // Best-effort cleanup
        }
    }

    public static string ComputeFileSha256Hex(string filePath)
    {
        using FileStream fs = File.OpenRead(filePath);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    public static async Task StreamTransferAsync(
        PreparedFileTransfer prepared,
        FramedControlTransport transport,
        CancellationToken ct)
    {
        byte[] buffer = new byte[ChunkSizeBytes];
        var shaList = new List<string>(prepared.SourceFilePaths.Count);

        for (int fileIdx = 0; fileIdx < prepared.SourceFilePaths.Count; fileIdx++)
        {
            string srcPath = prepared.SourceFilePaths[fileIdx];
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long offset = 0;

            await using var fs = new FileStream(srcPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            while (!ct.IsCancellationRequested)
            {
                int read = await fs.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read <= 0) break;

                hasher.AppendData(buffer.AsSpan(0, read));
                byte[] slice = read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
                await transport.SendAsync(
                    MessageType.FileTransferChunk,
                    PacketCodec.EncodeFileTransferChunk(new FileTransferChunkPayload(prepared.Offer.TransferId, fileIdx, offset, slice)),
                    ct).ConfigureAwait(false);
                offset += read;
            }

            shaList.Add(Convert.ToHexString(hasher.GetHashAndReset()));
        }

        await transport.SendAsync(
            MessageType.FileTransferComplete,
            PacketCodec.EncodeFileTransferComplete(new FileTransferCompletePayload(prepared.Offer.TransferId, shaList)),
            ct).ConfigureAwait(false);
    }

    private static string EnsureUniqueTopName(string candidate, HashSet<string> used)
    {
        if (used.Add(candidate)) return candidate;

        string baseName = Path.GetFileNameWithoutExtension(candidate);
        string ext = Path.GetExtension(candidate);
        int idx = 2;
        while (true)
        {
            string next = $"{baseName} ({idx}){ext}";
            if (used.Add(next)) return next;
            idx++;
        }
    }
}

/// <summary>
/// Writes incoming file chunks sequentially into a sandboxed transfer directory and validates SHA-256 hashes.
/// </summary>
public sealed class IncomingFileTransfer : IDisposable
{
    private readonly FileOfferPayload _offer;
    private readonly string _transferDir;
    private readonly List<string> _destFilePaths;
    private readonly List<string> _topLevelDestPaths;

    private int _openIndex = -1;
    private FileStream? _openStream;
    private bool _disposed;

    public IncomingFileTransfer(FileOfferPayload offer)
    {
        _offer = offer;
        FileTransferService.CleanupOldInboxFolders(keepLatest: 2);

        _transferDir = Path.Combine(FileTransferService.InboxRootDir, offer.TransferId.ToString());
        Directory.CreateDirectory(_transferDir);

        _topLevelDestPaths = offer.TopLevelRelativePaths
            .Select(top => FileTransferService.ResolveSafeDestinationPath(_transferDir, top))
            .ToList();

        foreach (string topPath in _topLevelDestPaths)
        {
            // If this top-level entry is a folder (not listed as a direct file entry), pre-create directory
            bool isSingleFile = offer.Files.Any(f =>
                string.Equals(
                    FileTransferService.ResolveSafeDestinationPath(_transferDir, f.RelativePath),
                    topPath,
                    StringComparison.OrdinalIgnoreCase));
            if (!isSingleFile)
            {
                Directory.CreateDirectory(topPath);
            }
        }

        long totalBytes = 0;
        if (offer.Files.Count > FileTransferService.MaxFiles)
            throw new InvalidDataException("Too many files in transfer offer.");

        _destFilePaths = new List<string>(offer.Files.Count);
        foreach (FileEntryInfo f in offer.Files)
        {
            if (f.Length < 0) throw new InvalidDataException("Negative file size.");
            totalBytes += f.Length;
            if (totalBytes > FileTransferService.MaxTotalBytes)
                throw new InvalidDataException("Transfer exceeds size cap.");

            string dest = FileTransferService.ResolveSafeDestinationPath(_transferDir, f.RelativePath);
            string? parent = Path.GetDirectoryName(dest);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

            if (f.Length == 0)
            {
                using var _ = File.Create(dest);
            }
            _destFilePaths.Add(dest);
        }
    }

    public ulong TransferId => _offer.TransferId;

    public void WriteChunk(FileTransferChunkPayload chunk)
    {
        if (chunk.TransferId != _offer.TransferId)
            throw new InvalidDataException("Mismatched transfer ID.");
        if (chunk.FileIndex < 0 || chunk.FileIndex >= _offer.Files.Count)
            throw new InvalidDataException("Invalid file index.");

        FileEntryInfo entry = _offer.Files[chunk.FileIndex];
        if (_openIndex != chunk.FileIndex)
        {
            _openStream?.Dispose();
            _openStream = new FileStream(_destFilePaths[chunk.FileIndex], FileMode.Create, FileAccess.Write, FileShare.None);
            _openIndex = chunk.FileIndex;
        }

        if (_openStream is null || chunk.Offset != _openStream.Position || _openStream.Position + chunk.Data.Length > entry.Length)
            throw new InvalidDataException("Unexpected chunk offset or size overflow.");

        _openStream.Write(chunk.Data);
    }

    public IReadOnlyList<string> FinalizeAndVerify(FileTransferCompletePayload complete)
    {
        _openStream?.Flush();
        _openStream?.Dispose();
        _openStream = null;
        _openIndex = -1;

        if (complete.TransferId != _offer.TransferId || complete.FileSha256HexList.Count != _offer.Files.Count)
            throw new InvalidDataException("File transfer completion count mismatch.");

        for (int i = 0; i < _offer.Files.Count; i++)
        {
            var fi = new FileInfo(_destFilePaths[i]);
            if (!fi.Exists || fi.Length != _offer.Files[i].Length)
                throw new InvalidDataException($"File size mismatch for {_offer.Files[i].RelativePath}.");

            string actualSha = FileTransferService.ComputeFileSha256Hex(_destFilePaths[i]);
            if (!string.Equals(actualSha, complete.FileSha256HexList[i], StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"SHA-256 verification failed for {_offer.Files[i].RelativePath}.");
        }

        return _topLevelDestPaths;
    }

    public void CleanupOnFailure()
    {
        Dispose();
        try
        {
            if (Directory.Exists(_transferDir)) Directory.Delete(_transferDir, recursive: true);
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _openStream?.Dispose();
        _openStream = null;
    }
}
