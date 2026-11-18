using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace LanKvm.Protocol;

public sealed record ControlFrame(MessageType Type, byte[] Payload);

public readonly record struct PinChallengePayload(ulong SessionId, byte[] ServerNonce);

public readonly record struct PinResponsePayload(
    AuthMode Mode,
    string ClientId,
    byte[] ClientNonce,
    byte[] Credential,
    string ClientName,
    int ScreenWidth,
    int ScreenHeight);

public readonly record struct AuthResultPayload(
    bool Accepted,
    ulong SessionId,
    byte[] UdpSessionKey,
    string HostName,
    int HostWidth,
    int HostHeight,
    string Reason,
    string IssuedClientId = "",
    byte[]? IssuedToken = null,
    string AppVersion = "",
    string ExeSha256 = "");

public readonly record struct UpdateChunkPayload(long Offset, long TotalLength, byte[] Data);

public readonly record struct UpdateCompletePayload(string Sha256Hex);

public readonly record struct FileEntryInfo(string RelativePath, long Length);

public readonly record struct FileOfferPayload(
    ulong TransferId,
    IReadOnlyList<string> TopLevelRelativePaths,
    IReadOnlyList<FileEntryInfo> Files);

public readonly record struct FileTransferRequestPayload(ulong TransferId);

public readonly record struct FileTransferChunkPayload(ulong TransferId, int FileIndex, long Offset, byte[] Data);

public readonly record struct FileTransferCompletePayload(ulong TransferId, IReadOnlyList<string> FileSha256HexList);

public readonly record struct SwitchScreenPayload(bool ToClient, ScreenEdge EntryEdge, float Ratio, bool IsHotkeyToggle = false);

public readonly record struct EdgeReturnPayload(ScreenEdge ReturnEdge, float Ratio);

public readonly record struct MouseButtonPayload(MouseButtonKind Button, bool IsDown);

public readonly record struct MouseWheelPayload(int Delta, bool IsHorizontal);

public readonly record struct KeyEventPayload(ushort VirtualKey, ushort ScanCode, bool IsExtended, bool IsKeyUp);

public readonly record struct UdpFallbackMotionPayload(int Dx, int Dy);

/// <summary>
/// Length-prefixed binary framing and payload codecs for TCP control messages.
/// Wire format: [PayloadLength+1 (4B LE)][MessageType (1B)][Payload (N bytes)].
/// </summary>
public static class PacketCodec
{
    public const int MaxPayloadBytes = 25 * 1024 * 1024; // 25 MB safety limit
    public const int ProtocolVersion = 1;

    public static async ValueTask WriteFrameAsync(
        Stream stream,
        MessageType type,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        if (payload.Length > MaxPayloadBytes)
        {
            throw new InvalidOperationException($"Payload size {payload.Length} exceeds limit {MaxPayloadBytes}.");
        }

        int bodyLength = 1 + payload.Length;
        byte[] header = ArrayPool<byte>.Shared.Rent(5);
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(0, 4), bodyLength);
            header[4] = (byte)type;
            await stream.WriteAsync(header.AsMemory(0, 5), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }

        if (!payload.IsEmpty)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static ValueTask<ControlFrame?> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken = default) =>
        ReadFrameAsync(stream, new byte[4], cancellationToken);

    public static async ValueTask<ControlFrame?> ReadFrameAsync(
        Stream stream,
        byte[] lenBuf,
        CancellationToken cancellationToken = default)
    {
        int firstRead = await ReadExactOrZeroOnEofAsync(stream, lenBuf, cancellationToken).ConfigureAwait(false);
        if (firstRead == 0)
        {
            return null;
        }

        int bodyLength = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
        if (bodyLength < 1 || bodyLength > MaxPayloadBytes + 1)
        {
            throw new InvalidDataException($"Invalid control frame length: {bodyLength}.");
        }

        byte[] body = new byte[bodyLength];
        await stream.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);

        var type = (MessageType)body[0];
        byte[] payload = bodyLength == 1 ? Array.Empty<byte>() : body.AsSpan(1).ToArray();
        return new ControlFrame(type, payload);
    }

    private static async ValueTask<int> ReadExactOrZeroOnEofAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                if (offset == 0)
                {
                    return 0;
                }
                throw new EndOfStreamException("Unexpected EOF while reading frame header.");
            }
            offset += n;
        }
        return offset;
    }

    // --- Payload Serializers ---

    public static byte[] EncodePinChallenge(in PinChallengePayload p)
    {
        byte[] buf = new byte[8 + 2 + p.ServerNonce.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(0, 8), p.SessionId);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(8, 2), (ushort)p.ServerNonce.Length);
        p.ServerNonce.CopyTo(buf.AsSpan(10));
        return buf;
    }

    public static PinChallengePayload DecodePinChallenge(ReadOnlySpan<byte> data)
    {
        ulong sessionId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(0, 8));
        ushort len = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2));
        return new PinChallengePayload(sessionId, data.Slice(10, len).ToArray());
    }

    public static byte[] EncodePinResponse(in PinResponsePayload p)
    {
        byte[] clientIdBytes = Encoding.UTF8.GetBytes(p.ClientId ?? string.Empty);
        byte[] nameBytes = Encoding.UTF8.GetBytes(p.ClientName);
        int size = 1 + 2 + clientIdBytes.Length + 2 + p.ClientNonce.Length + 2 + p.Credential.Length + 2 + nameBytes.Length + 8;
        byte[] buf = new byte[size];
        int pos = 0;
        buf[pos++] = (byte)p.Mode;
        WriteBytes16(buf, ref pos, clientIdBytes);
        WriteBytes16(buf, ref pos, p.ClientNonce);
        WriteBytes16(buf, ref pos, p.Credential);
        WriteBytes16(buf, ref pos, nameBytes);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(pos, 4), p.ScreenWidth);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(pos + 4, 4), p.ScreenHeight);
        return buf;
    }

    public static PinResponsePayload DecodePinResponse(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        var mode = (AuthMode)data[pos++];
        string clientId = Encoding.UTF8.GetString(ReadBytes16(data, ref pos));
        byte[] nonce = ReadBytes16(data, ref pos);
        byte[] cred = ReadBytes16(data, ref pos);
        string name = Encoding.UTF8.GetString(ReadBytes16(data, ref pos));
        int width = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos, 4));
        int height = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos + 4, 4));
        return new PinResponsePayload(mode, clientId, nonce, cred, name, width, height);
    }

    public static byte[] EncodeAuthResult(in AuthResultPayload p)
    {
        byte[] hostBytes = Encoding.UTF8.GetBytes(p.HostName);
        byte[] reasonBytes = Encoding.UTF8.GetBytes(p.Reason);
        byte[] issuedIdBytes = Encoding.UTF8.GetBytes(p.IssuedClientId ?? string.Empty);
        byte[] issuedToken = p.IssuedToken ?? Array.Empty<byte>();
        byte[] appVerBytes = Encoding.UTF8.GetBytes(p.AppVersion ?? string.Empty);
        byte[] shaBytes = Encoding.UTF8.GetBytes(p.ExeSha256 ?? string.Empty);

        int size = 1 + 8 + 2 + p.UdpSessionKey.Length + 2 + hostBytes.Length + 8 +
                   2 + reasonBytes.Length + 2 + issuedIdBytes.Length + 2 + issuedToken.Length +
                   2 + appVerBytes.Length + 2 + shaBytes.Length;
        byte[] buf = new byte[size];
        int pos = 0;
        buf[pos++] = p.Accepted ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos, 8), p.SessionId);
        pos += 8;
        WriteBytes16(buf, ref pos, p.UdpSessionKey);
        WriteBytes16(buf, ref pos, hostBytes);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(pos, 4), p.HostWidth);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(pos + 4, 4), p.HostHeight);
        pos += 8;
        WriteBytes16(buf, ref pos, reasonBytes);
        WriteBytes16(buf, ref pos, issuedIdBytes);
        WriteBytes16(buf, ref pos, issuedToken);
        WriteBytes16(buf, ref pos, appVerBytes);
        WriteBytes16(buf, ref pos, shaBytes);
        return buf;
    }

    public static AuthResultPayload DecodeAuthResult(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        bool accepted = data[pos++] != 0;
        ulong sessionId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(pos, 8));
        pos += 8;
        byte[] udpKey = ReadBytes16(data, ref pos);
        string hostName = Encoding.UTF8.GetString(ReadBytes16(data, ref pos));
        int width = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos, 4));
        int height = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(pos + 4, 4));
        pos += 8;
        string reason = Encoding.UTF8.GetString(ReadBytes16(data, ref pos));
        string issuedId = pos < data.Length ? Encoding.UTF8.GetString(ReadBytes16(data, ref pos)) : string.Empty;
        byte[] issuedToken = pos < data.Length ? ReadBytes16(data, ref pos) : Array.Empty<byte>();
        string appVer = pos < data.Length ? Encoding.UTF8.GetString(ReadBytes16(data, ref pos)) : string.Empty;
        string exeSha = pos < data.Length ? Encoding.UTF8.GetString(ReadBytes16(data, ref pos)) : string.Empty;
        return new AuthResultPayload(accepted, sessionId, udpKey, hostName, width, height, reason, issuedId, issuedToken, appVer, exeSha);
    }

    public static byte[] EncodeUpdateChunk(in UpdateChunkPayload p)
    {
        byte[] buf = new byte[16 + p.Data.Length];
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(0, 8), p.Offset);
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(8, 8), p.TotalLength);
        p.Data.CopyTo(buf.AsSpan(16));
        return buf;
    }

    public static UpdateChunkPayload DecodeUpdateChunk(ReadOnlySpan<byte> data)
    {
        long offset = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        long total = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(8, 8));
        return new UpdateChunkPayload(offset, total, data.Slice(16).ToArray());
    }

    public static byte[] EncodeUpdateComplete(string sha256Hex) => Encoding.UTF8.GetBytes(sha256Hex);

    public static UpdateCompletePayload DecodeUpdateComplete(ReadOnlySpan<byte> data) =>
        new(Encoding.UTF8.GetString(data));

    public static byte[] EncodeSwitchScreen(in SwitchScreenPayload p)
    {
        byte[] buf = new byte[7];
        buf[0] = p.ToClient ? (byte)1 : (byte)0;
        buf[1] = (byte)p.EntryEdge;
        BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(2, 4), p.Ratio);
        buf[6] = p.IsHotkeyToggle ? (byte)1 : (byte)0;
        return buf;
    }

    public static SwitchScreenPayload DecodeSwitchScreen(ReadOnlySpan<byte> data) =>
        new(
            data[0] != 0,
            (ScreenEdge)data[1],
            BinaryPrimitives.ReadSingleLittleEndian(data.Slice(2, 4)),
            data.Length >= 7 && data[6] != 0);

    public static byte[] EncodeEdgeReturn(in EdgeReturnPayload p)
    {
        byte[] buf = new byte[5];
        buf[0] = (byte)p.ReturnEdge;
        BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(1, 4), p.Ratio);
        return buf;
    }

    public static EdgeReturnPayload DecodeEdgeReturn(ReadOnlySpan<byte> data) =>
        new((ScreenEdge)data[0], BinaryPrimitives.ReadSingleLittleEndian(data.Slice(1, 4)));

    public static byte[] EncodeMouseButton(in MouseButtonPayload p) =>
        [(byte)p.Button, p.IsDown ? (byte)1 : (byte)0];

    public static MouseButtonPayload DecodeMouseButton(ReadOnlySpan<byte> data) =>
        new((MouseButtonKind)data[0], data[1] != 0);

    public static byte[] EncodeMouseWheel(in MouseWheelPayload p)
    {
        byte[] buf = new byte[5];
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0, 4), p.Delta);
        buf[4] = p.IsHorizontal ? (byte)1 : (byte)0;
        return buf;
    }

    public static MouseWheelPayload DecodeMouseWheel(ReadOnlySpan<byte> data) =>
        new(BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4)), data[4] != 0);

    public static byte[] EncodeKeyEvent(in KeyEventPayload p)
    {
        byte[] buf = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(0, 2), p.VirtualKey);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(2, 2), p.ScanCode);
        buf[4] = p.IsExtended ? (byte)1 : (byte)0;
        buf[5] = p.IsKeyUp ? (byte)1 : (byte)0;
        return buf;
    }

    public static KeyEventPayload DecodeKeyEvent(ReadOnlySpan<byte> data) =>
        new(
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(0, 2)),
            BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2)),
            data[4] != 0,
            data[5] != 0);

    public static byte[] EncodeUdpFallbackMotion(int dx, int dy)
    {
        byte[] buf = new byte[8];
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0, 4), dx);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4, 4), dy);
        return buf;
    }

    public static UdpFallbackMotionPayload DecodeUdpFallbackMotion(ReadOnlySpan<byte> data) =>
        new(
            BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4, 4)));

    public static byte[] EncodeHeartbeat(long timestampTicks)
    {
        byte[] buf = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(buf, timestampTicks);
        return buf;
    }

    public static long DecodeHeartbeat(ReadOnlySpan<byte> data) =>
        BinaryPrimitives.ReadInt64LittleEndian(data);

    public static byte[] EncodeFileOffer(in FileOfferPayload p)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);
        bw.Write(p.TransferId);
        bw.Write(p.TopLevelRelativePaths.Count);
        foreach (string top in p.TopLevelRelativePaths)
        {
            bw.Write(top);
        }
        bw.Write(p.Files.Count);
        foreach (FileEntryInfo f in p.Files)
        {
            bw.Write(f.RelativePath);
            bw.Write(f.Length);
        }
        bw.Flush();
        return ms.ToArray();
    }

    public static FileOfferPayload DecodeFileOffer(byte[] data)
    {
        using var ms = new MemoryStream(data);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        ulong id = br.ReadUInt64();
        int topCount = br.ReadInt32();
        if (topCount < 0 || topCount > 256) throw new InvalidDataException("Invalid top-level file count.");
        var tops = new List<string>(topCount);
        for (int i = 0; i < topCount; i++) tops.Add(br.ReadString());

        int fileCount = br.ReadInt32();
        if (fileCount < 0 || fileCount > 500) throw new InvalidDataException("Invalid file entry count.");
        var files = new List<FileEntryInfo>(fileCount);
        for (int i = 0; i < fileCount; i++)
        {
            string rel = br.ReadString();
            long len = br.ReadInt64();
            files.Add(new FileEntryInfo(rel, len));
        }
        return new FileOfferPayload(id, tops, files);
    }

    public static byte[] EncodeFileTransferRequest(ulong transferId)
    {
        byte[] buf = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, transferId);
        return buf;
    }

    public static FileTransferRequestPayload DecodeFileTransferRequest(ReadOnlySpan<byte> data) =>
        new(BinaryPrimitives.ReadUInt64LittleEndian(data));

    public static byte[] EncodeFileTransferChunk(in FileTransferChunkPayload p)
    {
        byte[] buf = new byte[20 + p.Data.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(0, 8), p.TransferId);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8, 4), p.FileIndex);
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(12, 8), p.Offset);
        p.Data.CopyTo(buf.AsSpan(20));
        return buf;
    }

    public static FileTransferChunkPayload DecodeFileTransferChunk(ReadOnlySpan<byte> data) =>
        new(
            BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(0, 8)),
            BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4)),
            BinaryPrimitives.ReadInt64LittleEndian(data.Slice(12, 8)),
            data.Slice(20).ToArray());

    public static byte[] EncodeFileTransferComplete(in FileTransferCompletePayload p)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);
        bw.Write(p.TransferId);
        bw.Write(p.FileSha256HexList.Count);
        foreach (string sha in p.FileSha256HexList) bw.Write(sha);
        bw.Flush();
        return ms.ToArray();
    }

    public static FileTransferCompletePayload DecodeFileTransferComplete(byte[] data)
    {
        using var ms = new MemoryStream(data);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        ulong id = br.ReadUInt64();
        int count = br.ReadInt32();
        if (count < 0 || count > 500) throw new InvalidDataException("Invalid SHA list count.");
        var hashes = new List<string>(count);
        for (int i = 0; i < count; i++) hashes.Add(br.ReadString());
        return new FileTransferCompletePayload(id, hashes);
    }

    private static void WriteBytes16(byte[] dest, ref int pos, ReadOnlySpan<byte> src)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(dest.AsSpan(pos, 2), (ushort)src.Length);
        pos += 2;
        src.CopyTo(dest.AsSpan(pos));
        pos += src.Length;
    }

    private static byte[] ReadBytes16(ReadOnlySpan<byte> src, ref int pos)
    {
        ushort len = BinaryPrimitives.ReadUInt16LittleEndian(src.Slice(pos, 2));
        pos += 2;
        byte[] result = src.Slice(pos, len).ToArray();
        pos += len;
        return result;
    }
}

/// <summary>
/// Serializes concurrent TCP writes on a single control stream.
/// </summary>
public sealed class FramedControlTransport : IDisposable
{
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly byte[] _readLenBuf = new byte[4];
    private bool _disposed;

    public FramedControlTransport(Stream stream)
    {
        _stream = stream;
    }

    public async ValueTask SendAsync(
        MessageType type,
        ReadOnlyMemory<byte> payload = default,
        CancellationToken cancellationToken = default)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await PacketCodec.WriteFrameAsync(_stream, type, payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public ValueTask<ControlFrame?> ReceiveAsync(CancellationToken cancellationToken = default) =>
        PacketCodec.ReadFrameAsync(_stream, _readLenBuf, cancellationToken);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _writeLock.Dispose();
    }
}
