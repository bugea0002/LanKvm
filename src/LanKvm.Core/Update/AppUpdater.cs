using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LanKvm.Core.Update;

public sealed record GitHubReleaseInfo(
    string TagVersion,
    string DownloadUrl,
    string? Sha256DownloadUrl,
    string HtmlUrl);

/// <summary>
/// Handles version comparison, self-replacing updates (--apply-update),
/// and optional GitHub Releases update discovery and verification.
/// </summary>
public static class AppUpdater
{
    public static string GetCurrentVersionString()
    {
        var asm = typeof(AppUpdater).Assembly;
        string? infoVer = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(infoVer))
        {
            int plus = infoVer.IndexOf('+');
            return plus > 0 ? infoVer[..plus] : infoVer;
        }
        Version? v = asm.GetName().Version;
        return v is not null ? $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}" : "1.0.0";
    }

    public static bool IsNewerVersion(string candidate, string current)
    {
        if (!TryParseSemVer(candidate, out Version? cVer) || !TryParseSemVer(current, out Version? curVer))
        {
            return false;
        }
        return cVer > curVer;
    }

    public static bool TryParseSemVer(string raw, out Version? version)
    {
        version = null;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        string cleaned = raw.Trim().TrimStart('v', 'V');
        int dash = cleaned.IndexOf('-');
        if (dash > 0) cleaned = cleaned[..dash];
        int plus = cleaned.IndexOf('+');
        if (plus > 0) cleaned = cleaned[..plus];
        return Version.TryParse(cleaned, out version);
    }

    public static (bool CanServeSelf, string Version, string Sha256Hex, string ExePath) GetSelfExecutableInfo()
    {
        string version = GetCurrentVersionString();
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath) ||
            !File.Exists(exePath) ||
            !exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(exePath).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
        {
            return (false, version, string.Empty, string.Empty);
        }

        string sha = ComputeFileSha256Hex(exePath);
        return (true, version, sha, exePath);
    }

    public static string ComputeFileSha256Hex(string filePath)
    {
        using FileStream fs = File.OpenRead(filePath);
        byte[] hash = SHA256.HashData(fs);
        return Convert.ToHexString(hash);
    }

    public static string GetStagingUpdatePath()
    {
        Directory.CreateDirectory(ConfigStore.LocalDataDir);
        return Path.Combine(ConfigStore.LocalDataDir, "LanKvm.update.exe");
    }

    /// <summary>
    /// Processes --apply-update / --cleanup-update / --minimized CLI arguments on startup.
    /// Returns true if the process was launched solely as an updater and should exit immediately.
    /// </summary>
    public static bool HandleStartupArgs(string[] args, out bool startMinimized)
    {
        startMinimized = args.Any(a => string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase));

        for (int i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--cleanup-update", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                string stale = args[i + 1];
                TryDeleteWithRetry(stale);
            }
            else if (string.Equals(args[i], "--apply-update", StringComparison.OrdinalIgnoreCase) && i + 2 < args.Length)
            {
                if (int.TryParse(args[i + 1], out int oldPid))
                {
                    string targetExe = args[i + 2];
                    ApplyUpdateAndRelaunch(oldPid, targetExe, startMinimized);
                    return true;
                }
            }
        }

        return false;
    }

    public static void LaunchApplyUpdateAndExit(string stagedExePath, bool restartMinimized)
    {
        string? currentExe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(currentExe) || !File.Exists(stagedExePath))
        {
            throw new InvalidOperationException("업데이트 적용 대상 파일 경로를 찾을 수 없습니다.");
        }

        int pid = Environment.ProcessId;
        string minArg = restartMinimized ? " --minimized" : string.Empty;
        Process.Start(new ProcessStartInfo
        {
            FileName = stagedExePath,
            Arguments = $"--apply-update {pid} \"{currentExe}\"{minArg}",
            UseShellExecute = false
        });
    }

    private static void ApplyUpdateAndRelaunch(int oldPid, string targetExePath, bool startMinimized)
    {
        try
        {
            using var oldProc = Process.GetProcessById(oldPid);
            oldProc.WaitForExit(15000);
        }
        catch
        {
            // Already exited
        }

        string? selfExe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(selfExe) || !File.Exists(selfExe)) return;

        for (int attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                File.Copy(selfExe, targetExePath, overwrite: true);
                break;
            }
            catch (IOException) when (attempt < 19)
            {
                Thread.Sleep(250);
            }
            catch (UnauthorizedAccessException) when (attempt < 19)
            {
                Thread.Sleep(250);
            }
        }

        string minArg = startMinimized ? " --minimized" : string.Empty;
        Process.Start(new ProcessStartInfo
        {
            FileName = targetExePath,
            Arguments = $"--cleanup-update \"{selfExe}\"{minArg}",
            UseShellExecute = false
        });
    }

    private static void TryDeleteWithRetry(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        for (int i = 0; i < 10; i++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch
            {
                Thread.Sleep(200);
            }
        }
    }

    public static bool IsValidGitHubRepo(string ownerRepo) =>
        !string.IsNullOrWhiteSpace(ownerRepo) &&
        Regex.IsMatch(ownerRepo.Trim(), @"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$") &&
        !ownerRepo.Contains("..", StringComparison.Ordinal);

    public static bool IsTrustedGitHubDownloadUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)) return false;
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) return false;

        string host = uri.Host;
        return host.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("objects.githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("release-assets.githubusercontent.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase);
    }

    public static async Task<GitHubReleaseInfo?> CheckGitHubLatestAsync(string ownerRepo, CancellationToken ct = default)
    {
        string trimmed = ownerRepo.Trim().Trim('/');
        if (!IsValidGitHubRepo(trimmed))
        {
            throw new ArgumentException("GitHub 저장소는 '사용자명/저장소명' 형식으로 입력하세요.");
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("LanKvm-Updater/1.1");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

        string url = $"https://api.github.com/repos/{trimmed}/releases/latest";
        using HttpResponseMessage resp = await http.GetAsync(url, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        JsonElement root = doc.RootElement;

        string tag = root.GetProperty("tag_name").GetString() ?? string.Empty;
        string htmlUrl = root.TryGetProperty("html_url", out var h) ? (h.GetString() ?? string.Empty) : string.Empty;

        string? exeUrl = null;
        string? shaUrl = null;
        if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement asset in assets.EnumerateArray())
            {
                string name = asset.GetProperty("name").GetString() ?? string.Empty;
                string dl = asset.GetProperty("browser_download_url").GetString() ?? string.Empty;
                if (name.Equals("LanKvm.exe", StringComparison.OrdinalIgnoreCase))
                {
                    exeUrl = dl;
                }
                else if (name.Equals("LanKvm.exe.sha256", StringComparison.OrdinalIgnoreCase))
                {
                    shaUrl = dl;
                }
            }
        }

        if (string.IsNullOrEmpty(exeUrl) || !IsTrustedGitHubDownloadUrl(exeUrl)) return null;
        if (!string.IsNullOrEmpty(shaUrl) && !IsTrustedGitHubDownloadUrl(shaUrl)) shaUrl = null;
        return new GitHubReleaseInfo(tag, exeUrl, shaUrl, htmlUrl);
    }

    public static async Task<string> DownloadGitHubUpdateAsync(GitHubReleaseInfo release, CancellationToken ct = default)
    {
        if (!IsTrustedGitHubDownloadUrl(release.DownloadUrl))
        {
            throw new InvalidOperationException("신뢰할 수 없는 업데이트 다운로드 URL입니다.");
        }
        if (string.IsNullOrEmpty(release.Sha256DownloadUrl) || !IsTrustedGitHubDownloadUrl(release.Sha256DownloadUrl))
        {
            throw new InvalidOperationException("릴리즈에 LanKvm.exe.sha256 검증 파일이 없어 업데이트를 중단했습니다.");
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("LanKvm-Updater/1.1");

        string shaText = await http.GetStringAsync(release.Sha256DownloadUrl, ct).ConfigureAwait(false);
        string? expectedSha = shaText.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
        if (string.IsNullOrEmpty(expectedSha) || expectedSha.Length != 64)
        {
            throw new InvalidDataException("유효한 SHA-256 체크섬을 읽을 수 없습니다.");
        }

        const long maxUpdateBytes = 512L * 1024 * 1024;
        string stagingPath = GetStagingUpdatePath();
        using (HttpResponseMessage resp = await http.GetAsync(release.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
        {
            resp.EnsureSuccessStatusCode();
            if (resp.Content.Headers.ContentLength is long len && len > maxUpdateBytes)
            {
                throw new InvalidDataException("업데이트 파일 크기가 허용 한도를 초과합니다.");
            }

            await using Stream netStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await using FileStream fs = File.Create(stagingPath);
            byte[] buf = new byte[81920];
            long totalRead = 0;
            int read;
            while ((read = await netStream.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
            {
                totalRead += read;
                if (totalRead > maxUpdateBytes)
                {
                    throw new InvalidDataException("업데이트 파일 크기가 허용 한도를 초과합니다.");
                }
                await fs.WriteAsync(buf.AsMemory(0, read), ct).ConfigureAwait(false);
            }
        }

        string actualSha = ComputeFileSha256Hex(stagingPath);
        if (!string.Equals(actualSha, expectedSha, StringComparison.OrdinalIgnoreCase))
        {
            TryDeleteWithRetry(stagingPath);
            throw new InvalidDataException("다운로드한 파일의 SHA-256 검증에 실패했습니다.");
        }

        return stagingPath;
    }
}
