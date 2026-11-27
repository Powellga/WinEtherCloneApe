using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace WinEtherCloneApe
{
    public enum FeedKind
    {
        /// <summary>One IPv4 or IPv6 address or CIDR range per line</summary>
        IpList,
        /// <summary>Spamhaus JSON lines: {"cidr":"2001:db8::/32", ...}</summary>
        SpamhausJson,
        /// <summary>One domain per line; a listed domain also covers its subdomains</summary>
        DomainList
    }

    public sealed class ThreatFeed
    {
        public required string Name { get; init; }
        public required string Description { get; init; }
        public required string Url { get; init; }
        public required string FileName { get; init; }
        public FeedKind Kind { get; init; } = FeedKind.IpList;
    }

    public sealed class ThreatMatch
    {
        public ThreatMatch(string indicator, IReadOnlyList<ThreatFeed> feeds, string? viaDomain = null)
        {
            Indicator = indicator;
            Feeds = feeds;
            ViaDomain = viaDomain;
        }

        /// <summary>The address or domain that matched.</summary>
        public string Indicator { get; }
        public IReadOnlyList<ThreatFeed> Feeds { get; }

        /// <summary>Set when an address is a threat because a listed domain resolved to it.</summary>
        public string? ViaDomain { get; }

        public string Summary => (ViaDomain != null ? $"via domain {ViaDomain}: " : "") + string.Join(", ", Feeds.Select(f => f.Name));

        public ThreatMatch Merge(ThreatMatch other) => new(Indicator,
            Feeds.Concat(other.Feeds).Distinct().ToList(), ViaDomain ?? other.ViaDomain);
    }

    /// <summary>
    /// Checks IPv4 and IPv6 addresses and domain names against free public threat lists.
    /// Lists are cached on disk and re-downloaded when older than 12 hours (checked at startup
    /// and every hour while running), so the app also works offline with the last copy.
    /// </summary>
    public sealed class ThreatIntel
    {
        public static readonly ThreatFeed[] Feeds =
        {
            new()
            {
                Name = "FireHOL Level 1",
                Description = "Known attackers, malware hosts and hijacked networks (aggregate of Spamhaus DROP, dshield and others)",
                Url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                FileName = "firehol_level1.netset"
            },
            new()
            {
                Name = "Feodo Tracker",
                Description = "Botnet command-and-control servers (abuse.ch)",
                Url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                FileName = "feodo_ipblocklist.txt"
            },
            new()
            {
                Name = "Emerging Threats",
                Description = "Compromised hosts (Proofpoint Emerging Threats)",
                Url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                FileName = "et_compromised_ips.txt"
            },
            new()
            {
                Name = "CINS Army",
                Description = "Hosts with a poor reputation, seen attacking networks (CINS Score)",
                Url = "https://cinsscore.com/list/ci-badguys.txt",
                FileName = "cins_badguys.txt"
            },
            new()
            {
                Name = "HaGeZi Threat IPs",
                Description = "Malware, phishing and command-and-control server addresses (HaGeZi Threat Intelligence Feeds)",
                Url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt",
                FileName = "hagezi_tif_ips.txt"
            },
            new()
            {
                Name = "Spamhaus DROP IPv6",
                Description = "IPv6 networks run by criminals or hijacked (Spamhaus Don't Route Or Peer)",
                Url = "https://www.spamhaus.org/drop/drop_v6.json",
                FileName = "spamhaus_drop_v6.json",
                Kind = FeedKind.SpamhausJson
            },
            new()
            {
                Name = "HaGeZi Threat Domains",
                Description = "Malware, phishing, scam and command-and-control domains (HaGeZi Threat Intelligence Feeds)",
                Url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
                FileName = "hagezi_tif_domains.txt",
                Kind = FeedKind.DomainList
            },
            new()
            {
                Name = "Phishing Army",
                Description = "Phishing domains (PhishTank, OpenPhish, CERT.PL and others)",
                Url = "https://phishing.army/download/phishing_army_blocklist.txt",
                FileName = "phishing_army.txt",
                Kind = FeedKind.DomainList
            },
        };

        private static readonly TimeSpan RefreshAge = TimeSpan.FromHours(12);
        private static readonly Regex CidrJson = new("\"cidr\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.Compiled);

        private sealed class FeedData
        {
            public required ThreatFeed Feed { get; init; }
            public uint[] V4Starts { get; init; } = Array.Empty<uint>();
            public uint[] V4Ends { get; init; } = Array.Empty<uint>();
            public UInt128[] V6Starts { get; init; } = Array.Empty<UInt128>();
            public UInt128[] V6Ends { get; init; } = Array.Empty<UInt128>();
            public HashSet<string> Domains { get; init; } = new();
            public DateTime Downloaded { get; init; }
            public int Count => V4Starts.Length + V6Starts.Length + Domains.Count;
        }

        private readonly string folder = Path.Combine(AppSettings.DataFolder, "threatfeeds");
        private volatile FeedData[] data = Array.Empty<FeedData>();
        private readonly SemaphoreSlim refreshLock = new(1, 1);
        private List<string> lastFailures = new();

        public event Action? Updated;

        /// <summary>Goes up every time the lists change, so callers know to re-check.</summary>
        public int Version { get; private set; }

        public string Status { get; private set; } = "Loading threat feeds...";
        public DateTime? LastRefreshAttempt { get; private set; }

        public int Ipv4Ranges => data.Sum(d => d.V4Starts.Length);
        public int Ipv6Ranges => data.Sum(d => d.V6Starts.Length);
        public int DomainCount => data.Sum(d => d.Domains.Count);
        public int LoadedFeeds => data.Length;
        public IReadOnlyList<string> Failures => lastFailures;

        public async Task InitializeAsync(HttpClient http)
        {
            LoadFromDisk();
            if (data.Length > 0)
            {
                Status = BuildStatus();
                Updated?.Invoke();
            }
            await RefreshAsync(http);
        }

        /// <summary>Downloads any list older than 12 hours. Safe to call often.</summary>
        public async Task RefreshAsync(HttpClient http)
        {
            if (!await refreshLock.WaitAsync(0)) return;
            try
            {
                LastRefreshAttempt = DateTime.Now;
                Directory.CreateDirectory(folder);
                var failed = new List<string>();
                bool changed = false;

                foreach (var feed in Feeds)
                {
                    string path = Path.Combine(folder, feed.FileName);
                    if (File.Exists(path) && DateTime.Now - File.GetLastWriteTime(path) < RefreshAge) continue;

                    try
                    {
                        string text = await http.GetStringAsync(feed.Url);
                        if (Parse(feed, text, DateTime.Now).Count == 0) throw new InvalidDataException("empty list");
                        await File.WriteAllTextAsync(path, text);
                        changed = true;
                    }
                    catch
                    {
                        // Keep using the cached copy, if there is one
                        failed.Add(feed.Name);
                    }
                }

                lastFailures = failed;
                if (changed || data.Length == 0) LoadFromDisk();
                Status = BuildStatus();
                Updated?.Invoke();
            }
            finally
            {
                refreshLock.Release();
            }
        }

        private string BuildStatus()
        {
            var current = data;
            if (current.Length == 0) return "No threat feeds available (offline?)";
            var oldest = current.Min(d => d.Downloaded);
            string text = $"{current.Length} of {Feeds.Length} lists loaded\n" +
                          $"{Ipv4Ranges:N0} IPv4 ranges\n{Ipv6Ranges:N0} IPv6 ranges\n{DomainCount:N0} domains\n" +
                          $"Oldest list: {oldest:g}";
            if (lastFailures.Count > 0)
                text += $"\nCould not download: {string.Join(", ", lastFailures)}";
            return text;
        }

        private void LoadFromDisk()
        {
            var loaded = new List<FeedData>();
            foreach (var feed in Feeds)
            {
                string path = Path.Combine(folder, feed.FileName);
                if (!File.Exists(path)) continue;
                try
                {
                    var parsed = Parse(feed, File.ReadAllText(path), File.GetLastWriteTime(path));
                    if (parsed.Count > 0) loaded.Add(parsed);
                }
                catch
                {
                    // Unreadable cache file - it will be downloaded again next time
                }
            }
            data = loaded.ToArray();
            Version++;
        }

        private static FeedData Parse(ThreatFeed feed, string text, DateTime downloaded)
        {
            if (feed.Kind == FeedKind.DomainList)
            {
                var domains = new HashSet<string>(StringComparer.Ordinal);
                foreach (string raw in text.Split('\n'))
                {
                    string line = raw.Trim();
                    int comment = line.IndexOf('#');
                    if (comment >= 0) line = line[..comment].Trim();
                    if (line.Length == 0) continue;

                    // Accept "domain", "*.domain" and hosts-file lines ("0.0.0.0 domain")
                    string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    string domain = parts[^1].TrimStart('*', '.').TrimEnd('.').ToLowerInvariant();
                    if (domain.Contains('.') && !IPAddress.TryParse(domain, out _)) domains.Add(domain);
                }
                return new FeedData { Feed = feed, Domains = domains, Downloaded = downloaded };
            }

            IEnumerable<string> tokens = feed.Kind == FeedKind.SpamhausJson
                ? CidrJson.Matches(text).Select(m => m.Groups[1].Value)
                : text.Split('\n').Select(raw =>
                {
                    string line = raw;
                    int comment = line.IndexOfAny(new[] { '#', ';' });
                    if (comment >= 0) line = line[..comment];
                    line = line.Trim();
                    return line.Length == 0 ? "" : line.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries)[0];
                });

            var v4 = new List<(UInt128 Start, UInt128 End)>();
            var v6 = new List<(UInt128 Start, UInt128 End)>();
            foreach (string token in tokens)
            {
                if (token.Length == 0) continue;
                int slash = token.IndexOf('/');
                string ipPart = slash >= 0 ? token[..slash] : token;
                if (!IPAddress.TryParse(ipPart, out var ip)) continue;

                bool isV4 = ip.AddressFamily == AddressFamily.InterNetwork;
                int bits = isV4 ? 32 : 128;
                int prefix = bits;
                if (slash >= 0 && !int.TryParse(token[(slash + 1)..], out prefix)) continue;
                if (prefix < 0 || prefix > bits) continue;

                UInt128 value = ToNumber(ip);
                UInt128 hostMask = prefix == bits ? UInt128.Zero : (UInt128.One << (bits - prefix)) - 1;
                UInt128 start = value & ~hostMask;
                (isV4 ? v4 : v6).Add((start, start | hostMask));
            }

            var (v4Starts, v4Ends) = Merge(v4);
            var (v6Starts, v6Ends) = Merge(v6);
            return new FeedData
            {
                Feed = feed,
                V4Starts = v4Starts.Select(s => (uint)s).ToArray(),
                V4Ends = v4Ends.Select(e => (uint)e).ToArray(),
                V6Starts = v6Starts,
                V6Ends = v6Ends,
                Downloaded = downloaded
            };
        }

        private static (UInt128[] Starts, UInt128[] Ends) Merge(List<(UInt128 Start, UInt128 End)> ranges)
        {
            ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
            var starts = new List<UInt128>(ranges.Count);
            var ends = new List<UInt128>(ranges.Count);
            foreach (var r in ranges)
            {
                if (starts.Count > 0 && (ends[^1] == UInt128.MaxValue || r.Start <= ends[^1] + 1))
                {
                    if (r.End > ends[^1]) ends[^1] = r.End;
                }
                else
                {
                    starts.Add(r.Start);
                    ends.Add(r.End);
                }
            }
            return (starts.ToArray(), ends.ToArray());
        }

        private static UInt128 ToNumber(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (b.Length == 4) return BinaryPrimitives.ReadUInt32BigEndian(b);
            return new UInt128(BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(0, 8)), BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(8, 8)));
        }

        /// <summary>True for addresses that can be on a public blocklist (not private, multicast or reserved).</summary>
        public static bool IsCheckable(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (IpUtil.IsPrivate(ip) || IpUtil.IsMulticast(ip) || IpUtil.IsReserved(ip)) return false;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && (ip.Equals(IPAddress.IPv6Loopback) || ip.Equals(IPAddress.IPv6None)))
                return false;

            // Documentation ranges never route on the internet; FireHOL lists them as bogons
            byte[] b = ip.GetAddressBytes();
            if (b.Length == 4 && ((b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
                                  (b[0] == 203 && b[1] == 0 && b[2] == 113)))
                return false;
            if (b.Length == 16 && b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false;
            return true;
        }

        public ThreatMatch? Check(IPAddress ip)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            // FireHOL Level 1 lists private and reserved ranges as bogons - never flag those
            if (!IsCheckable(ip)) return null;

            List<ThreatFeed>? hits = null;
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                uint value = (uint)ToNumber(ip);
                foreach (var d in data)
                    if (d.V4Starts.Length > 0 && Contains(d.V4Starts, d.V4Ends, value))
                        (hits ??= new List<ThreatFeed>()).Add(d.Feed);
            }
            else
            {
                UInt128 value = ToNumber(ip);
                foreach (var d in data)
                    if (d.V6Starts.Length > 0 && Contains(d.V6Starts, d.V6Ends, value))
                        (hits ??= new List<ThreatFeed>()).Add(d.Feed);
            }
            return hits == null ? null : new ThreatMatch(IpUtil.Normalize(ip), hits);
        }

        /// <summary>Checks a domain and each parent domain (a.b.evil.com, b.evil.com, evil.com).</summary>
        public ThreatMatch? CheckDomain(string name)
        {
            string domain = name.Trim().TrimEnd('.').ToLowerInvariant();
            if (domain.Length == 0 || !domain.Contains('.')) return null;

            List<ThreatFeed>? hits = null;
            string? matched = null;
            foreach (var d in data)
            {
                if (d.Domains.Count == 0) continue;
                string candidate = domain;
                while (true)
                {
                    if (d.Domains.Contains(candidate))
                    {
                        (hits ??= new List<ThreatFeed>()).Add(d.Feed);
                        matched ??= candidate;
                        break;
                    }
                    int dot = candidate.IndexOf('.');
                    if (dot < 0 || candidate.IndexOf('.', dot + 1) < 0) break; // stop at "evil.com"
                    candidate = candidate[(dot + 1)..];
                }
            }
            return hits == null ? null : new ThreatMatch(matched ?? domain, hits);
        }

        private static bool Contains<T>(T[] starts, T[] ends, T value) where T : IComparable<T>
        {
            int idx = Array.BinarySearch(starts, value);
            if (idx >= 0) return true;
            idx = ~idx - 1;
            return idx >= 0 && ends[idx].CompareTo(value) >= 0;
        }

        /// <summary>A single listed IPv4 address, used by demo mode to show what a threat looks like.</summary>
        public string? SampleListedIp()
        {
            var feed = data.FirstOrDefault(d => d.Feed.Name == "Feodo Tracker") ?? data.FirstOrDefault(d => d.V4Starts.Length > 0);
            if (feed == null) return null;
            for (int i = 0; i < feed.V4Starts.Length; i++)
            {
                var ip = IpUtil.FromUInt(feed.V4Starts[i]);
                if (feed.V4Starts[i] == feed.V4Ends[i] && IsCheckable(ip))
                    return ip.ToString();
            }
            return null;
        }

        /// <summary>An address inside a listed IPv6 network, for demo mode.</summary>
        public string? SampleListedIpv6()
        {
            var feed = data.FirstOrDefault(d => d.V6Starts.Length > 0);
            if (feed == null) return null;
            UInt128 value = feed.V6Starts[0] + 0x10;
            Span<byte> b = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(b, (ulong)(value >> 64));
            BinaryPrimitives.WriteUInt64BigEndian(b[8..], (ulong)value);
            return new IPAddress(b).ToString();
        }

        /// <summary>A listed domain, for demo mode.</summary>
        public string? SampleListedDomain() =>
            data.FirstOrDefault(d => d.Domains.Count > 0)?.Domains.FirstOrDefault(d => d.Count(c => c == '.') == 1);
    }
}
