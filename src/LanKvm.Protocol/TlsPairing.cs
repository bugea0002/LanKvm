using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LanKvm.Protocol;

public static class TlsPairing
{
    public static string GenerateSixDigitPin() =>
        RandomNumberGenerator.GetInt32(100000, 1000000).ToString("D6");

    public static X509Certificate2 CreateOrLoadHostCertificate(string pfxPath)
    {
        if (File.Exists(pfxPath))
        {
            try
            {
                var loaded = new X509Certificate2(
                    pfxPath,
                    (string?)null,
                    X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
                if (loaded.NotAfter > DateTime.UtcNow.AddDays(30))
                {
                    return loaded;
                }
                loaded.Dispose();
            }
            catch
            {
                // Regenerate if corrupt or unreadable
            }
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=LanKvm-Host", ecdsa, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        byte[] pfxBytes = cert.Export(X509ContentType.Pfx);

        string? dir = Path.GetDirectoryName(pfxPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllBytes(pfxPath, pfxBytes);

        return new X509Certificate2(
            pfxBytes,
            (string?)null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
    }

    public static string GetCertificateFingerprint(X509Certificate cert)
    {
        byte[] hash = SHA256.HashData(cert.GetRawCertData());
        return Convert.ToHexString(hash);
    }

    public static string FormatFingerprintShort(string hexFingerprint)
    {
        if (hexFingerprint.Length < 16) return hexFingerprint;
        return $"{hexFingerprint[..4]}:{hexFingerprint[4..8]}:{hexFingerprint[8..12]}:{hexFingerprint[12..16]}";
    }

    public static byte[] ComputePinHmac(
        string pin,
        ReadOnlySpan<byte> serverNonce,
        ReadOnlySpan<byte> clientNonce,
        string serverCertFingerprintHex)
    {
        byte[] key = Encoding.UTF8.GetBytes(pin.Trim());
        byte[] fpBytes = Encoding.UTF8.GetBytes(serverCertFingerprintHex);

        byte[] data = new byte[serverNonce.Length + clientNonce.Length + fpBytes.Length];
        serverNonce.CopyTo(data);
        clientNonce.CopyTo(data.AsSpan(serverNonce.Length));
        fpBytes.CopyTo(data.AsSpan(serverNonce.Length + clientNonce.Length));

        return HMACSHA256.HashData(key, data);
    }

    public static bool VerifyPinHmac(
        string expectedPin,
        ReadOnlySpan<byte> serverNonce,
        ReadOnlySpan<byte> clientNonce,
        string serverCertFingerprintHex,
        ReadOnlySpan<byte> providedHmac)
    {
        byte[] expected = ComputePinHmac(expectedPin, serverNonce, clientNonce, serverCertFingerprintHex);
        return CryptographicOperations.FixedTimeEquals(expected, providedHmac);
    }

    public static string ComputeTokenHashHex(ReadOnlySpan<byte> rawToken) =>
        Convert.ToHexString(SHA256.HashData(rawToken));

    public static bool VerifyTokenHashHex(ReadOnlySpan<byte> rawToken, string expectedHashHex)
    {
        if (string.IsNullOrEmpty(expectedHashHex)) return false;
        try
        {
            byte[] actual = SHA256.HashData(rawToken);
            byte[] expected = Convert.FromHexString(expectedHashHex);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

/// <summary>
/// Tracks consecutive authentication failures per client IP to block brute-force PIN attempts.
/// </summary>
public sealed class PinRateLimiter
{
    private readonly int _maxFailures;
    private readonly TimeSpan _lockoutDuration;
    private readonly object _gate = new();
    private readonly Dictionary<string, FailureState> _states = new(StringComparer.Ordinal);

    public PinRateLimiter(int maxFailures = 5, TimeSpan? lockoutDuration = null)
    {
        _maxFailures = Math.Max(1, maxFailures);
        _lockoutDuration = lockoutDuration ?? TimeSpan.FromSeconds(60);
    }

    public bool IsLockedOut(string key, DateTimeOffset nowUtc, out TimeSpan remaining)
    {
        lock (_gate)
        {
            if (_states.TryGetValue(key, out FailureState state) && state.LockedUntil > nowUtc)
            {
                remaining = state.LockedUntil - nowUtc;
                return true;
            }
            remaining = TimeSpan.Zero;
            return false;
        }
    }

    public void RecordFailure(string key, DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            if (_states.Count > 256)
            {
                var expired = _states.Where(kv => kv.Value.LockedUntil <= nowUtc && kv.Value.LastAttempt + TimeSpan.FromMinutes(10) < nowUtc)
                                     .Select(kv => kv.Key)
                                     .ToList();
                foreach (string k in expired) _states.Remove(k);
            }

            _states.TryGetValue(key, out FailureState state);
            int count = state.FailureCount + 1;
            DateTimeOffset lockedUntil = count >= _maxFailures ? nowUtc + _lockoutDuration : DateTimeOffset.MinValue;
            _states[key] = new FailureState(count >= _maxFailures ? 0 : count, lockedUntil, nowUtc);
        }
    }

    public void RecordSuccess(string key)
    {
        lock (_gate)
        {
            _states.Remove(key);
        }
    }

    private readonly record struct FailureState(int FailureCount, DateTimeOffset LockedUntil, DateTimeOffset LastAttempt);
}
