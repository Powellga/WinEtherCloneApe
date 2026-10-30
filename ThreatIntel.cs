using System.IO;
using System.Net;
using System.Net.Http;

namespace WinEtherCloneApe
{
    public sealed class ThreatFeed
    {
        public required string Name { get; init; }
        public required string Description { get; init; }
        public required string Url { get; init; }
        public required string FileName { get; init; }
    }

    public sealed class ThreatMatch
    {
        public ThreatMatch(string ip, IReadOnlyList<ThreatFeed> feeds)
        {
            Ip = ip;
            Feeds = feeds;
        }

        public string Ip { get; }
        public IReadOnlyList<ThreatFeed> Feeds { get; }
        public string Summary => string.Join(", ", Feeds.Select(f => f.Name));
    }

    /// <summary>
    /// Checks IPv4 addresses against free public blocklists. Lists are cached on disk and
    /// refreshed when older than 12 hours, so the app still works offline with the last copy.
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
        };

        private static readonly TimeSpan RefreshAge = TimeSpan.FromHours(12);

        private sealed class FeedData
        {
            public required ThreatFeed Feed { get; init; }
            public required uint[] Starts { get; init; }
            public required uint[] Ends { get; init; }
        }

        private readonly string folder = Path.Combine(AppSettings.DataFolder, "threatfeeds");
        private volatile FeedData[] data = Array.Empty<FeedData>();

        public event Action? Updated;

        public string Status { get; private set; } = "Loading threat feeds...";

        public async Task InitializeAsync(HttpClient http)
        {
            LoadFromDisk();
            if (data.Length > 0)
            {
                Status = BuildStatus("cached");
                Updated?.Invoke();
            }

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
                    if (Parse(text).Starts.Length == 0) throw new InvalidDataException("empty list");
                    await File.WriteAllTextAsync(path, text);
                    changed = true;
                }
                catch
                {
                    failed.Add(feed.Name);
                }
            }

            if (changed) LoadFromDisk();

            Status = BuildStatus(changed ? "updated" : "cached");
            if (failed.Count > 0)
                Status += $"\nCould not download: {string.Join(", ", failed)}";
            Updated?.Invoke();
        }

        private string BuildStatus(string how)
        {
            var current = data;
            if (current.Length == 0) return "No threat feeds available (offline?)";
            int entries = current.Sum(d => d.Starts.Length);
            return $"{current.Length} of {Feeds.Length} feeds {how}\n{entries:N0} blocked ranges\nChecked {DateTime.Now:t}";
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
                    var (starts, ends) = Parse(File.ReadAllText(path));
                    if (starts.Length > 0)
                        loaded.Add(new FeedData { Feed = feed, Starts = starts, Ends = ends });
                }
                catch
                {
                    // Unreadable cache file - it will be downloaded again next time
                }
            }
            data = loaded.ToArray();
        }

        /// <summary>Parses "1.2.3.4" and "1.2.3.0/24" lines into sorted, merged ranges.</summary>
        private static (uint[] Starts, uint[] Ends) Parse(string text)
        {
            var ranges = new List<(uint Start, uint End)>();
            char[] separators = { ' ', '\t', ',' };

            foreach (string raw in text.Split('\n'))
            {
                string line = raw;
                int comment = line.IndexOfAny(new[] { '#', ';' });
                if (comment >= 0) line = line[..comment];
                line = line.Trim();
                if (line.Length == 0) continue;

                string token = line.Split(separators, StringSplitOptions.RemoveEmptyEntries)[0];
                int slash = token.IndexOf('/');
                string ipPart = slash >= 0 ? token[..slash] : token;
                int prefix = 32;
                if (slash >= 0 && !int.TryParse(token[(slash + 1)..], out prefix)) continue;
                if (prefix < 0 || prefix > 32 || ipPart.Count(c => c == '.') != 3) continue;
                if (!IPAddress.TryParse(ipPart, out var ip) || !IpUtil.TryToUInt(ip, out uint value)) continue;

                uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
                uint start = value & mask;
                ranges.Add((start, start | ~mask));
            }

            ranges.Sort((a, b) => a.Start.CompareTo(b.Start));

            var starts = new List<uint>(ranges.Count);
            var ends = new List<uint>(ranges.Count);
            foreach (var r in ranges)
            {
                if (starts.Count > 0 && (ends[^1] == uint.MaxValue || r.Start <= ends[^1] + 1))
                {
                    ends[^1] = Math.Max(ends[^1], r.End);
                }
                else
                {
                    starts.Add(r.Start);
                    ends.Add(r.End);
                }
            }
            return (starts.ToArray(), ends.ToArray());
        }

        public ThreatMatch? Check(IPAddress ip)
        {
            // FireHOL Level 1 lists private and reserved ranges as bogons - never flag those
            if (IpUtil.IsPrivate(ip) || IpUtil.IsMulticast(ip) || IpUtil.IsReserved(ip)) return null;
            if (!IpUtil.TryToUInt(ip, out uint value)) return null;

            List<ThreatFeed>? hits = null;
            foreach (var d in data)
            {
                if (Contains(d, value))
                    (hits ??= new List<ThreatFeed>()).Add(d.Feed);
            }
            return hits == null ? null : new ThreatMatch(ip.ToString(), hits);
        }

        private static bool Contains(FeedData d, uint value)
        {
            int idx = Array.BinarySearch(d.Starts, value);
            if (idx >= 0) return true;
            idx = ~idx - 1;
            return idx >= 0 && d.Ends[idx] >= value;
        }

        /// <summary>A single listed address, used by demo mode to show what a threat looks like.</summary>
        public string? SampleListedIp()
        {
            var feed = data.FirstOrDefault(d => d.Feed.Name == "Feodo Tracker") ?? data.FirstOrDefault();
            if (feed == null) return null;
            for (int i = 0; i < feed.Starts.Length; i++)
            {
                var ip = IpUtil.FromUInt(feed.Starts[i]);
                if (feed.Starts[i] == feed.Ends[i] && !IpUtil.IsPrivate(ip) && !IpUtil.IsReserved(ip))
                    return ip.ToString();
            }
            return null;
        }
    }
}
