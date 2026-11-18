using System.Runtime.InteropServices;

namespace LanKvm.Core.Native;

/// <summary>
/// Wraps Windows DPAPI (CryptProtectData / CryptUnprotectData) bound to CurrentUser
/// so stored pairing tokens in config.json are encrypted at rest.
/// </summary>
public static class DpapiHelper
{
    private const uint CryptProtectUiForbidden = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string? szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        IntPtr ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static string ProtectToBase64(ReadOnlySpan<byte> plaintext)
    {
        byte[] raw = plaintext.ToArray();
        IntPtr inPtr = Marshal.AllocHGlobal(raw.Length);
        var outBlob = new DATA_BLOB();
        try
        {
            Marshal.Copy(raw, 0, inPtr, raw.Length);
            var inBlob = new DATA_BLOB { cbData = raw.Length, pbData = inPtr };
            if (!CryptProtectData(ref inBlob, "LanKvmDeviceToken", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outBlob))
            {
                throw new InvalidOperationException($"CryptProtectData failed ({Marshal.GetLastWin32Error()}).");
            }

            byte[] encrypted = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, encrypted, 0, outBlob.cbData);
            return Convert.ToBase64String(encrypted);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
        }
    }

    public static byte[]? TryUnprotectFromBase64(string? base64Ciphertext)
    {
        if (string.IsNullOrWhiteSpace(base64Ciphertext)) return null;

        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(base64Ciphertext);
        }
        catch (FormatException)
        {
            return null;
        }

        IntPtr inPtr = Marshal.AllocHGlobal(raw.Length);
        var outBlob = new DATA_BLOB();
        try
        {
            Marshal.Copy(raw, 0, inPtr, raw.Length);
            var inBlob = new DATA_BLOB { cbData = raw.Length, pbData = inPtr };
            if (!CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outBlob))
            {
                return null;
            }

            byte[] plain = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, plain, 0, outBlob.cbData);
            return plain;
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
        }
    }
}
