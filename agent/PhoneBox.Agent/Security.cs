using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PhoneBox.Agent;

/// <summary>
/// security.json next to config.json: switches for the risky defaults. Read once at start; restart the agent to apply.
/// A missing file is created with the safe defaults; a broken one is left alone and the safe defaults are used.
/// </summary>
public sealed class SecurityConfig
{
    public const string FileName = "security.json";

    /// <summary>Check GitHub for new releases in the background and install them (agent and phone app).</summary>
    public bool AutoUpdate { get; set; }

    /// <summary>Read Claude Code's files: its login token (quota widget), its sessions, and installing its permission hook.</summary>
    public bool ClaudeAccess { get; set; }

    /// <summary>
    /// Only the PhoneBox app may use the USB connection: the phone signs every request with <see cref="UsbKey"/>, which the
    /// agent hands it over adb. Other apps on the phone reach nothing. Needs the phone app from this fork.
    /// </summary>
    public bool UsbRequiresKey { get; set; } = true;

    /// <summary>Generated when empty. Delete it to give the phone a new key on the next plug-in.</summary>
    public string? UsbKey { get; set; }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static string PathNextTo(string configPath) => Path.Combine(Path.GetDirectoryName(configPath)!, FileName);

    /// <summary>The PC port "adb reverse" points the phone at: a separate, signed-only port when the key is required.</summary>
    public int UsbTargetPort(int agentPort) => UsbRequiresKey ? agentPort + 2 : agentPort;

    public static SecurityConfig Load(string path, ILogger? log = null)
    {
        SecurityConfig security;
        try
        {
            security = File.Exists(path) ? JsonSerializer.Deserialize<SecurityConfig>(File.ReadAllText(path), Json) ?? new() : new();
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            log?.LogWarning("{File} could not be read ({Error}); using the safe defaults", FileName, ex.Message);
            return new SecurityConfig { UsbKey = NewKey() }; // not saved: the user's file stays as it is
        }
        if (File.Exists(path) && IsValidKey(security.UsbKey)) return security;
        security.UsbKey = IsValidKey(security.UsbKey) ? security.UsbKey : NewKey();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        AppPaths.WriteAllTextPrivate(path, JsonSerializer.Serialize(security, Json));
        return security;
    }

    internal static string NewKey() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    internal static bool IsValidKey(string? key) => key is { Length: 64 } && key.All(Uri.IsHexDigit);
}

/// <summary>
/// Signature of a request over USB: HMAC-SHA256 of "METHOD\ntarget\ntime" with the USB key. A signature, not the key
/// itself, so an app that listens on the phone's port 8765 while the cable is out learns nothing it could reuse.
/// </summary>
public static class UsbSignature
{
    public const string TimeHeader = "X-PhoneBox-Time";
    public const string SignatureHeader = "X-PhoneBox-Signature";
    private const long MaxClockSkewMs = 5 * 60_000;

    public static string Sign(string key, string method, string target, long timeMs) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(Convert.FromHexString(key), Encoding.UTF8.GetBytes($"{method}\n{target}\n{timeMs}")));

    public static bool IsValid(string key, string method, string target, string? time, string? signature, long nowMs)
    {
        if (!long.TryParse(time, out var timeMs) || Math.Abs(nowMs - timeMs) > MaxClockSkewMs || signature is null) return false;
        var expected = Encoding.ASCII.GetBytes(Sign(key, method, target, timeMs));
        return CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(signature.ToLowerInvariant()));
    }
}
