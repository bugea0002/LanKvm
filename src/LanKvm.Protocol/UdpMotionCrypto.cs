using System.Buffers.Binary;
using System.Security.Cryptography;

namespace LanKvm.Protocol;

public enum UdpPacketKind : byte
{
    ClientHello = 0x01,
    MotionDelta = 0x02
}

/// <summary>
/// Authenticated and encrypted UDP framing using AES-256-GCM.
/// Packet layout: [Magic:2 ('L','K')][Kind:1][SessionId:8][Sequence:8][Ciphertext:N][Tag:16]
/// Nonce (12B) = [Direction:1 (0x01=C2S, 0x02=S2C)][Reserved:3][Sequence:8] so nonces never collide.
/// </summary>
public sealed class UdpMotionCrypto : IDisposable
{
    public const int HeaderSize = 19;
    public const int TagSize = 16;
    public const int HelloPayloadSize = 8;
    public const int MotionPayloadSize = 12;
    public const int HelloPacketSize = HeaderSize + HelloPayloadSize + TagSize;   // 43 bytes
    public const int MotionPacketSize = HeaderSize + MotionPayloadSize + TagSize; // 47 bytes

    private const byte Magic0 = (byte)'L';
    private const byte Magic1 = (byte)'K';
    private const byte DirClientToServer = 0x01;
    private const byte DirServerToClient = 0x02;

    private readonly AesGcm _aesGcm;
    private readonly ulong _sessionId;
    private readonly ReplayWindow _c2sReplay = new();
    private readonly ReplayWindow _s2cReplay = new();
    private long _sendSeq;
    private bool _disposed;

    public UdpMotionCrypto(ulong sessionId, ReadOnlySpan<byte> key32)
    {
        if (key32.Length != 32)
            throw new ArgumentException("UDP session key must be 32 bytes (AES-256).", nameof(key32));

        _sessionId = sessionId;
        _aesGcm = new AesGcm(key32, TagSize);
    }

    public int EncryptClientHello(long clientTicks, Span<byte> destination)
    {
        ulong seq = (ulong)Interlocked.Increment(ref _sendSeq);
        Span<byte> plaintext = stackalloc byte[HelloPayloadSize];
        BinaryPrimitives.WriteInt64LittleEndian(plaintext, clientTicks);
        return EncryptInternal(UdpPacketKind.ClientHello, DirClientToServer, seq, plaintext, destination);
    }

    public int EncryptMotionDelta(int dx, int dy, uint flags, Span<byte> destination)
    {
        ulong seq = (ulong)Interlocked.Increment(ref _sendSeq);
        Span<byte> plaintext = stackalloc byte[MotionPayloadSize];
        BinaryPrimitives.WriteInt32LittleEndian(plaintext.Slice(0, 4), dx);
        BinaryPrimitives.WriteInt32LittleEndian(plaintext.Slice(4, 4), dy);
        BinaryPrimitives.WriteUInt32LittleEndian(plaintext.Slice(8, 4), flags);
        return EncryptInternal(UdpPacketKind.MotionDelta, DirServerToClient, seq, plaintext, destination);
    }

    public bool TryDecryptClientHello(ReadOnlySpan<byte> packet, out ulong sessionId, out long clientTicks)
    {
        sessionId = 0;
        clientTicks = 0;
        if (packet.Length != HelloPacketSize) return false;
        if (!TryDecryptInternal(packet, UdpPacketKind.ClientHello, DirClientToServer, _c2sReplay, out sessionId, out byte[]? plain))
            return false;

        clientTicks = BinaryPrimitives.ReadInt64LittleEndian(plain);
        return true;
    }

    public bool TryDecryptMotionDelta(
        ReadOnlySpan<byte> packet,
        out ulong sessionId,
        out ulong sequence,
        out int dx,
        out int dy,
        out uint flags)
    {
        sessionId = 0;
        sequence = 0;
        dx = 0;
        dy = 0;
        flags = 0;
        if (packet.Length != MotionPacketSize) return false;

        if (!TryDecryptInternal(packet, UdpPacketKind.MotionDelta, DirServerToClient, _s2cReplay, out sessionId, out byte[]? plain))
            return false;

        sequence = BinaryPrimitives.ReadUInt64LittleEndian(packet.Slice(11, 8));
        dx = BinaryPrimitives.ReadInt32LittleEndian(plain.AsSpan(0, 4));
        dy = BinaryPrimitives.ReadInt32LittleEndian(plain.AsSpan(4, 4));
        flags = BinaryPrimitives.ReadUInt32LittleEndian(plain.AsSpan(8, 4));
        return true;
    }

    private int EncryptInternal(
        UdpPacketKind kind,
        byte direction,
        ulong seq,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        int totalSize = HeaderSize + plaintext.Length + TagSize;
        if (destination.Length < totalSize)
            throw new ArgumentException("Destination buffer too small.", nameof(destination));

        Span<byte> header = destination.Slice(0, HeaderSize);
        header[0] = Magic0;
        header[1] = Magic1;
        header[2] = (byte)kind;
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(3, 8), _sessionId);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(11, 8), seq);

        Span<byte> nonce = stackalloc byte[12];
        BuildNonce(direction, seq, nonce);

        Span<byte> ciphertext = destination.Slice(HeaderSize, plaintext.Length);
        Span<byte> tag = destination.Slice(HeaderSize + plaintext.Length, TagSize);
        _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, header);
        return totalSize;
    }

    private bool TryDecryptInternal(
        ReadOnlySpan<byte> packet,
        UdpPacketKind expectedKind,
        byte direction,
        ReplayWindow replayWindow,
        out ulong sessionId,
        out byte[] plaintext)
    {
        sessionId = 0;
        plaintext = Array.Empty<byte>();
        if (packet.Length < HeaderSize + TagSize) return false;

        ReadOnlySpan<byte> header = packet.Slice(0, HeaderSize);
        if (header[0] != Magic0 || header[1] != Magic1 || header[2] != (byte)expectedKind)
            return false;

        sessionId = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(3, 8));
        if (sessionId != _sessionId) return false;

        ulong seq = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(11, 8));
        if (seq == 0 || !replayWindow.CheckAndPreview(seq))
            return false;

        int cipherLen = packet.Length - HeaderSize - TagSize;
        ReadOnlySpan<byte> ciphertext = packet.Slice(HeaderSize, cipherLen);
        ReadOnlySpan<byte> tag = packet.Slice(HeaderSize + cipherLen, TagSize);

        Span<byte> nonce = stackalloc byte[12];
        BuildNonce(direction, seq, nonce);

        byte[] decrypted = new byte[cipherLen];
        try
        {
            _aesGcm.Decrypt(nonce, ciphertext, tag, decrypted, header);
        }
        catch (CryptographicException)
        {
            return false;
        }

        // Only commit replay state after tag verification succeeds.
        if (!replayWindow.TryAccept(seq))
            return false;

        plaintext = decrypted;
        return true;
    }

    private static void BuildNonce(byte direction, ulong seq, Span<byte> nonce)
    {
        nonce.Clear();
        nonce[0] = direction;
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4, 8), seq);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _aesGcm.Dispose();
    }

    private sealed class ReplayWindow
    {
        private ulong _highest;
        private ulong _bitmap;
        private readonly object _gate = new();

        public bool CheckAndPreview(ulong seq)
        {
            lock (_gate)
            {
                if (seq > _highest) return true;
                ulong diff = _highest - seq;
                if (diff >= 64) return false;
                return (_bitmap & (1UL << (int)diff)) == 0;
            }
        }

        public bool TryAccept(ulong seq)
        {
            lock (_gate)
            {
                if (seq > _highest)
                {
                    ulong shift = seq - _highest;
                    _bitmap = shift >= 64 ? 1UL : ((_bitmap << (int)shift) | 1UL);
                    _highest = seq;
                    return true;
                }

                ulong diff = _highest - seq;
                if (diff >= 64) return false;
                ulong mask = 1UL << (int)diff;
                if ((_bitmap & mask) != 0) return false;
                _bitmap |= mask;
                return true;
            }
        }
    }
}
