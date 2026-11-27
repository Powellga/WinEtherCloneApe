using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace WinEtherCloneApe
{
    /// <summary>Everything known this session about one internet address. Kept after its node leaves the screen.</summary>
    public sealed class ObservedHost
    {
        public required IPAddress Address { get; init; }
        public required string Ip { get; init; }
        public DateTime FirstSeen { get; init; }
        public DateTime LastSeen { get; set; }
        public long Packets { get; set; }
        public long Bytes { get; set; }
        public SortedSet<int> Ports { get; } = new();
        public SortedSet<string> Protocols { get; } = new();
        public SortedSet<string> LocalDevices { get; } = new();
        public SortedSet<string> DnsNames { get; } = new();
        public string? HostName { get; set; }

        /// <summary>"Your device" when a local device opened the connection, "The remote host" when it came in.</summary>
        public string? StartedBy { get; set; }
        public bool StartedByFromSyn { get; set; }

        public ThreatMatch? Threat { get; set; }
        public DateTime? DetectedAt { get; set; }

        /// <summary>True when the address only matched after a list update, after traffic was already seen.</summary>
        public bool DetectedLater { get; set; }
    }

    /// <summary>A lookup of a listed domain by a device on this network.</summary>
    public sealed class DnsThreat
    {
        public required string Domain { get; init; }
        public required ThreatMatch Match { get; init; }
        public DateTime FirstSeen { get; init; }
        public DateTime LastSeen { get; set; }
        public int Lookups { get; set; }
        public SortedSet<string> Devices { get; } = new();
        public SortedSet<string> ResolvedTo { get; } = new();
    }

    /// <summary>
    /// The session's threat record. Every public address seen in any packet is registered here
    /// (including packets the display had to skip), checked against the lists, and re-checked
    /// whenever the lists change. Every DNS name looked up is checked too. Runs on the UI thread.
    /// </summary>
    public sealed class ThreatMonitor
    {
        private const int MaxHosts = 300_000;

        private readonly ThreatIntel intel;
        private readonly Dictionary<string, ObservedHost> hosts = new();
        private readonly Dictionary<string, DnsThreat> dnsThreats = new();
        private readonly HashSet<string> namesChecked = new();
        private int checkedVersion = -1;

        public ThreatMonitor(ThreatIntel intel) => this.intel = intel;

        /// <summary>Raised once per newly found threat (an address or a domain lookup).</summary>
        public event Action<ObservedHost>? HostThreatFound;
        public event Action<DnsThreat>? DnsThreatFound;

        public int AddressesChecked => hosts.Count;
        public int Ipv4Checked { get; private set; }
        public int Ipv6Checked { get; private set; }
        public int NamesChecked => namesChecked.Count;
        public long Rechecks { get; private set; }
        public DateTime? LastRecheck { get; private set; }

        public IEnumerable<ObservedHost> ThreatHosts => hosts.Values.Where(h => h.Threat != null);
        public IEnumerable<DnsThreat> DnsThreats => dnsThreats.Values;
        public int ThreatCount => hosts.Values.Count(h => h.Threat != null) + dnsThreats.Count;

        public ObservedHost? Get(string ip) => hosts.TryGetValue(ip, out var h) ? h : null;

        /// <summary>Registers an address (if new) and checks it. Returns null for private/multicast/reserved addresses.</summary>
        public ObservedHost? Ensure(IPAddress address, DateTime time)
        {
            if (!ThreatIntel.IsCheckable(address)) return null;
            string ip = IpUtil.Normalize(address);
            if (hosts.TryGetValue(ip, out var existing)) return existing;

            if (hosts.Count >= MaxHosts) Trim();
            var host = new ObservedHost { Address = address, Ip = ip, FirstSeen = time, LastSeen = time };
            hosts[ip] = host;
            if (address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv4MappedToIPv6) Ipv6Checked++;
            else Ipv4Checked++;

            if (intel.Check(address) is { } match) Flag(host, match, time, later: false);
            return host;
        }

        /// <summary>Adds one packet's details to the internet end(s) of the conversation.</summary>
        public void ObservePacket(IPAddress source, IPAddress destination, string protocol, int size,
            int sourcePort, int destinationPort, bool tcpSyn, DateTime time)
        {
            // This PC's own public addresses (for example a global IPv6 address) count as your device, not the internet
            var src = LocalNetwork.LocalAddresses.Contains(IpUtil.Normalize(source)) ? null : Ensure(source, time);
            var dst = LocalNetwork.LocalAddresses.Contains(IpUtil.Normalize(destination)) ? null : Ensure(destination, time);
            if (src != null) Update(src, IpUtil.Normalize(destination), dst == null, protocol, size, sourcePort, destinationPort, outgoing: false, tcpSyn, time);
            if (dst != null) Update(dst, IpUtil.Normalize(source), src == null, protocol, size, destinationPort, sourcePort, outgoing: true, tcpSyn, time);
        }

        private static void Update(ObservedHost host, string peer, bool peerIsLocal, string protocol, int size,
            int hostPort, int peerPort, bool outgoing, bool tcpSyn, DateTime time)
        {
            host.LastSeen = time;
            host.Packets++;
            host.Bytes += size;
            if (host.Protocols.Count < 8) host.Protocols.Add(protocol);
            // The service port is the lower of the two (443, not the random high port on the other side)
            if (hostPort > 0 && peerPort > 0 && host.Ports.Count < 24) host.Ports.Add(Math.Min(hostPort, peerPort));
            if (peerIsLocal && host.LocalDevices.Count < 32) host.LocalDevices.Add(peer);

            // Who opened the conversation: a TCP SYN says for sure; otherwise the first packet seen is a good guess
            string who = outgoing ? "Your device" : "The remote host";
            if (tcpSyn && !host.StartedByFromSyn)
            {
                host.StartedBy = who;
                host.StartedByFromSyn = true;
            }
            else if (host.StartedBy == null)
            {
                host.StartedBy = who;
            }
        }

        /// <summary>Checks a DNS lookup: the name itself, and marks the addresses it resolved to.</summary>
        public void ObserveDns(DnsInfo dns, IPAddress client, DateTime time)
        {
            string name = dns.QueryName.TrimEnd('.').ToLowerInvariant();
            if (name.Length == 0 || name.EndsWith(".local") || name.EndsWith(".arpa") || name.EndsWith(".lan")) return;
            if (namesChecked.Count < 500_000) namesChecked.Add(name);

            // Remember which names resolved to which address, for reports and tooltips
            foreach (var address in dns.Addresses)
            {
                if (Ensure(address, time) is { } resolved && resolved.DnsNames.Count < 8) resolved.DnsNames.Add(name);
            }

            var match = intel.CheckDomain(name);
            if (match == null) return;

            string device = IpUtil.Normalize(client);
            bool isNew = !dnsThreats.TryGetValue(name, out var threat);
            if (isNew)
            {
                threat = new DnsThreat { Domain = name, Match = match, FirstSeen = time, LastSeen = time };
                dnsThreats[name] = threat;
            }
            threat!.LastSeen = time;
            if (!dns.IsResponse || threat.Lookups == 0) threat.Lookups++;
            if (threat.Devices.Count < 32) threat.Devices.Add(device);

            foreach (var address in dns.Addresses)
            {
                if (Ensure(address, time) is not { } host) continue;
                threat.ResolvedTo.Add(host.Ip);
                if (host.LocalDevices.Count < 32) host.LocalDevices.Add(device);
                var viaDomain = new ThreatMatch(host.Ip, match.Feeds, name);
                if (host.Threat == null) Flag(host, viaDomain, time, later: false);
                else if (host.Threat.ViaDomain == null) host.Threat = host.Threat.Merge(viaDomain);
            }

            if (isNew) DnsThreatFound?.Invoke(threat);
        }

        /// <summary>Checks a reverse-DNS host name against the domain lists.</summary>
        public void ObserveHostName(string ip, string? hostName, DateTime time)
        {
            if (hostName == null || !hosts.TryGetValue(ip, out var host)) return;
            host.HostName = hostName;
            string name = hostName.TrimEnd('.').ToLowerInvariant();
            if (namesChecked.Count < 500_000) namesChecked.Add(name);
            if (host.Threat == null && intel.CheckDomain(name) is { } match)
                Flag(host, new ThreatMatch(ip, match.Feeds, name), time, later: false);
        }

        /// <summary>After the lists change, re-checks every address and name seen this session.</summary>
        public void RecheckIfListsChanged(DateTime now)
        {
            if (intel.Version == checkedVersion) return;
            // The first pass is the lists loading at startup, not an update, so nothing is "detected later"
            bool isUpdate = checkedVersion != -1;
            checkedVersion = intel.Version;
            Rechecks++;
            LastRecheck = now;

            foreach (var host in hosts.Values)
            {
                var match = intel.Check(host.Address);
                if (match == null && host.HostName != null && intel.CheckDomain(host.HostName) is { } byName)
                    match = new ThreatMatch(host.Ip, byName.Feeds, host.HostName);
                if (match == null && host.DnsNames.Select(n => intel.CheckDomain(n)).FirstOrDefault(m => m != null) is { } byDns)
                    match = new ThreatMatch(host.Ip, byDns.Feeds, byDns.Indicator);

                if (match == null) continue;
                if (host.Threat == null) Flag(host, match, now, later: isUpdate);
                else host.Threat = host.Threat.Merge(match);
            }
        }

        private void Flag(ObservedHost host, ThreatMatch match, DateTime time, bool later)
        {
            host.Threat = match;
            host.DetectedAt = time;
            host.DetectedLater = later && host.Packets > 0;
            HostThreatFound?.Invoke(host);
        }

        /// <summary>Very long sessions: forget the oldest clean addresses, never threats.</summary>
        private void Trim()
        {
            foreach (var old in hosts.Values.Where(h => h.Threat == null).OrderBy(h => h.LastSeen).Take(MaxHosts / 10).ToList())
                hosts.Remove(old.Ip);
        }

        public static string Describe(ObservedHost h)
        {
            var sb = new StringBuilder();
            sb.Append(h.Threat!.Summary);
            if (h.LocalDevices.Count > 0) sb.Append($" | your devices: {string.Join(", ", h.LocalDevices)}");
            if (h.StartedBy != null) sb.Append($" | started by: {h.StartedBy.ToLowerInvariant()}");
            if (h.Ports.Count > 0) sb.Append($" | ports: {string.Join(", ", h.Ports)}");
            if (h.DnsNames.Count > 0) sb.Append($" | names: {string.Join(", ", h.DnsNames)}");
            if (h.DetectedLater) sb.Append($" | matched after a list update; first seen {h.FirstSeen:g}");
            return sb.ToString();
        }

        /// <summary>Writes the full threat report as CSV (opens in Excel).</summary>
        public void ExportCsv(string path)
        {
            static string Q(string? s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
            var sb = new StringBuilder();
            sb.AppendLine("Type,Indicator,Host name,Lists,Via domain,Your devices,Started by,Ports,Protocols,Packets,Bytes,First seen,Last seen,Detected,Detected after list update");
            foreach (var h in ThreatHosts.OrderBy(h => h.DetectedAt))
            {
                sb.AppendLine(string.Join(",", Q("Address"), Q(h.Ip), Q(h.HostName), Q(string.Join("; ", h.Threat!.Feeds.Select(f => f.Name))),
                    Q(h.Threat.ViaDomain), Q(string.Join("; ", h.LocalDevices)), Q(h.StartedBy), Q(string.Join("; ", h.Ports)),
                    Q(string.Join("; ", h.Protocols)), h.Packets, h.Bytes, Q($"{h.FirstSeen:yyyy-MM-dd HH:mm:ss}"),
                    Q($"{h.LastSeen:yyyy-MM-dd HH:mm:ss}"), Q($"{h.DetectedAt:yyyy-MM-dd HH:mm:ss}"), h.DetectedLater ? "Yes" : "No"));
            }
            foreach (var d in DnsThreats.OrderBy(d => d.FirstSeen))
            {
                sb.AppendLine(string.Join(",", Q("DNS lookup"), Q(d.Domain), Q(""), Q(string.Join("; ", d.Match.Feeds.Select(f => f.Name))),
                    Q(d.Match.Indicator), Q(string.Join("; ", d.Devices)), Q("Your device"), Q("53"), Q("DNS"), d.Lookups, 0,
                    Q($"{d.FirstSeen:yyyy-MM-dd HH:mm:ss}"), Q($"{d.LastSeen:yyyy-MM-dd HH:mm:ss}"),
                    Q($"{d.FirstSeen:yyyy-MM-dd HH:mm:ss}"), "No"));
            }
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }
    }
}
