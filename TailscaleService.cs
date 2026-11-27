using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;

namespace WinEtherCloneApe
{
    public enum TailscaleKind
    {
        /// <summary>This PC's own Tailscale address</summary>
        ThisPc,
        /// <summary>Another device in the tailnet (100.x or fd7a:115c:a1e0:: address)</summary>
        Peer,
        /// <summary>Tailscale's built-in DNS server, 100.100.100.100</summary>
        MagicDns,
        /// <summary>The public internet address a peer's encrypted WireGuard traffic goes to</summary>
        Endpoint,
        /// <summary>Tailscale's own servers: coordination (login) and DERP relays</summary>
        Service
    }

    public sealed class TailscaleInfo
    {
        public TailscaleKind Kind { get; init; }
        public string Name { get; init; } = "";
        public string? DnsName { get; init; }
        public string? OS { get; init; }
        public bool? Online { get; init; }
        public string? Relay { get; init; }
        public bool ExitNode { get; init; }

        public string Description => Kind switch
        {
            TailscaleKind.ThisPc => "This PC on Tailscale",
            TailscaleKind.Peer => "Tailscale device",
            TailscaleKind.MagicDns => "Tailscale MagicDNS",
            TailscaleKind.Endpoint => $"Tailscale tunnel to {Name}",
            _ => "Tailscale server (login or relay)"
        };
    }

    /// <summary>
    /// Recognizes Tailscale addresses. Reads device names from "tailscale status --json" when the
    /// Tailscale app is installed, and falls back to address ranges when it is not.
    /// </summary>
    public sealed class TailscaleService
    {
        private static readonly byte[] TailscaleUlaPrefix = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };

        // Replaced whole on each refresh, so the UI thread always reads a complete set
        private Dictionary<string, TailscaleInfo> byIp = new();
        private int refreshing;

        /// <summary>True when this PC has an active Tailscale adapter.</summary>
        public bool AdapterPresent { get; private set; }

        /// <summary>Demo mode: treat 100.64.0.0/10 as Tailscale even without an adapter.</summary>
        public bool AssumeTailnet { get; set; }

        public string? TailnetName { get; private set; }
        public int PeerCount { get; private set; }

        public static string? FindCli()
        {
            var candidates = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tailscale", "tailscale.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Tailscale", "tailscale.exe"),
            };
            return candidates.FirstOrDefault(File.Exists);
        }

        /// <summary>Refreshes in the background; safe to call often, overlapping calls are skipped.</summary>
        public void RefreshInBackground()
        {
            if (Interlocked.Exchange(ref refreshing, 1) == 1) return;
            Task.Run(() =>
            {
                try { Refresh(); }
                catch { /* Tailscale info is a bonus; ranges still work without it */ }
                finally { Interlocked.Exchange(ref refreshing, 0); }
            });
        }

        private void Refresh()
        {
            AdapterPresent = NetworkInterface.GetAllNetworkInterfaces().Any(ni =>
                ni.OperationalStatus == OperationalStatus.Up &&
                (ni.Description.Contains("Tailscale", StringComparison.OrdinalIgnoreCase) ||
                 ni.Name.Contains("Tailscale", StringComparison.OrdinalIgnoreCase)));

            string? cli = FindCli();
            if (cli == null) return;

            var psi = new ProcessStartInfo(cli)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList = { "status", "--json" }
            };
            using var process = Process.Start(psi);
            if (process == null) return;
            var outputTask = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(8000))
            {
                try { process.Kill(); } catch { }
                return;
            }
            string json = outputTask.Result;
            if (string.IsNullOrWhiteSpace(json)) return;

            var map = new Dictionary<string, TailscaleInfo>();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("MagicDNSSuffix", out var suffix) && suffix.ValueKind == JsonValueKind.String)
                TailnetName = suffix.GetString();

            if (root.TryGetProperty("Self", out var self) && self.ValueKind == JsonValueKind.Object)
                AddDevice(map, self, TailscaleKind.ThisPc);

            int peers = 0;
            if (root.TryGetProperty("Peer", out var peerMap) && peerMap.ValueKind == JsonValueKind.Object)
            {
                foreach (var peer in peerMap.EnumerateObject())
                {
                    AddDevice(map, peer.Value, TailscaleKind.Peer);
                    peers++;
                }
            }

            PeerCount = peers;
            byIp = map;
        }

        private static void AddDevice(Dictionary<string, TailscaleInfo> map, JsonElement e, TailscaleKind kind)
        {
            string? hostName = Str(e, "HostName");
            string? dnsName = Str(e, "DNSName")?.TrimEnd('.');
            string name = dnsName?.Split('.')[0] is { Length: > 0 } shortName ? shortName : hostName ?? "Tailscale device";

            var info = new TailscaleInfo
            {
                Kind = kind,
                Name = name,
                DnsName = dnsName,
                OS = Str(e, "OS"),
                Online = e.TryGetProperty("Online", out var on) && on.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? on.GetBoolean() : null,
                Relay = Str(e, "Relay"),
                ExitNode = e.TryGetProperty("ExitNode", out var exit) && exit.ValueKind == JsonValueKind.True
            };

            if (e.TryGetProperty("TailscaleIPs", out var ips) && ips.ValueKind == JsonValueKind.Array)
            {
                foreach (var ip in ips.EnumerateArray())
                {
                    if (ip.GetString() is { } s && IPAddress.TryParse(s, out var addr))
                        map[IpUtil.Normalize(addr)] = info;
                }
            }

            // The public address its encrypted tunnel traffic currently goes to, e.g. "73.1.2.3:41641"
            if (kind == TailscaleKind.Peer && Str(e, "CurAddr") is { Length: > 0 } cur
                && ParseEndpoint(cur) is { } endpoint && !IpUtil.IsPrivate(endpoint))
            {
                map.TryAdd(IpUtil.Normalize(endpoint), new TailscaleInfo
                {
                    Kind = TailscaleKind.Endpoint,
                    Name = name,
                    DnsName = dnsName,
                    OS = info.OS,
                    Online = info.Online
                });
            }
        }

        private static string? Str(JsonElement e, string property) =>
            e.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        private static IPAddress? ParseEndpoint(string text)
        {
            if (IPEndPoint.TryParse(text, out var ep)) return ep.Address;
            return IPAddress.TryParse(text, out var addr) ? addr : null;
        }

        public static bool IsTailscaleUla(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
            var b = ip.GetAddressBytes();
            for (int i = 0; i < TailscaleUlaPrefix.Length; i++)
                if (b[i] != TailscaleUlaPrefix[i]) return false;
            return true;
        }

        public static bool IsCgnat(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            return b[0] == 100 && b[1] >= 64 && b[1] <= 127;
        }

        /// <summary>Returns Tailscale details for an address, or null when it has nothing to do with Tailscale.</summary>
        public TailscaleInfo? Identify(IPAddress address, string ip, string? hostName)
        {
            if (ip is "100.100.100.100" or "fd7a:115c:a1e0::53")
                return new TailscaleInfo { Kind = TailscaleKind.MagicDns, Name = "MagicDNS" };

            if (byIp.TryGetValue(ip, out var known)) return known;

            // 100.64.0.0/10 is also used by some internet providers (carrier-grade NAT),
            // so only treat it as Tailscale when this PC is on a tailnet
            if (IsTailscaleUla(address) || ((AdapterPresent || AssumeTailnet) && IsCgnat(address)))
                return new TailscaleInfo { Kind = TailscaleKind.Peer, Name = "Tailscale device" };

            if (hostName != null)
            {
                string h = hostName.TrimEnd('.').ToLowerInvariant();
                if (h.EndsWith(".tailscale.com") || h.EndsWith(".tailscale.io") || h == "tailscale.com")
                    return new TailscaleInfo { Kind = TailscaleKind.Service, Name = h.Split('.')[0] };
                if (h.EndsWith(".ts.net"))
                    return new TailscaleInfo { Kind = TailscaleKind.Peer, Name = h.Split('.')[0], DnsName = h };
            }

            return null;
        }
    }
}
