using System.Text.Json;
using System.Text.Json.Serialization;
using LanKvm.Protocol;

namespace LanKvm.Core;

public enum AppRole
{
    Host = 0,
    Client = 1
}

public enum SwitchHotkeyMode
{
    CtrlAltSpace = 0,
    ScrollLock = 1,
    Pause = 2,
    None = 3
}

public sealed record TrustedClientRecord(
    string ClientId,
    string ClientName,
    string TokenHashHex,
    DateTimeOffset PairedAtUtc);

public sealed record PairedServerRecord(
    string ClientId,
    string EncryptedTokenBase64,
    string ServerFingerprintHex);

public sealed class AppConfig
{
    public AppRole Role { get; set; } = AppRole.Host;
    public string HostIp { get; set; } = string.Empty;
    public int TcpPort { get; set; } = 24800;
    public int UdpPort { get; set; } = 24801;
    public ScreenEdge SwitchEdge { get; set; } = ScreenEdge.Right;
    public double ClientSensitivity { get; set; } = 1.0;
    public int EdgeResistancePx { get; set; } = 16;
    public SwitchHotkeyMode SwitchHotkey { get; set; } = SwitchHotkeyMode.CtrlAltSpace;
    public bool AutoLockOnFullscreen { get; set; } = true;
    public bool LockScreenEdge { get; set; } = false;
    public bool ClipboardSyncEnabled { get; set; } = true;
    public bool AutoReconnect { get; set; } = true;
    public bool AutoStartService { get; set; } = true;
    public bool StartWithWindows { get; set; } = false;
    public bool AllowPrivateNetworksOnly { get; set; } = true;
    public bool AutoSyncUpdateFromHost { get; set; } = true;
    public string GitHubRepo { get; set; } = string.Empty;
    public bool CheckGitHubUpdatesOnStart { get; set; } = false;
    public List<TrustedClientRecord> TrustedClients { get; set; } = new();
    public Dictionary<string, PairedServerRecord> PairedServers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> TrustedServerFingerprints { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public static class ConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string AppDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LanKvm");

    public static string LocalDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LanKvm");

    public static string ConfigFilePath => Path.Combine(AppDataDir, "config.json");
    public static string HostCertPath => Path.Combine(AppDataDir, "host-cert.pfx");

    public static AppConfig Load()
    {
        try
        {
            if (File.Exists(ConfigFilePath))
            {
                string json = File.ReadAllText(ConfigFilePath);
                var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
                if (cfg is not null)
                {
                    cfg.TrustedClients ??= new();
                    cfg.PairedServers ??= new(StringComparer.OrdinalIgnoreCase);
                    cfg.TrustedServerFingerprints ??= new(StringComparer.OrdinalIgnoreCase);
                    return cfg;
                }
            }
        }
        catch
        {
            // Fall back to defaults on corrupted config
        }

        return new AppConfig();
    }

    public static void Save(AppConfig config)
    {
        Directory.CreateDirectory(AppDataDir);
        string json = JsonSerializer.Serialize(config, JsonOptions);
        File.WriteAllText(ConfigFilePath, json);
    }
}
