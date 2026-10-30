using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace WinEtherCloneApe
{
    /// <summary>
    /// Reverse DNS lookups with a timeout, at most 8 at a time. Each IP is looked up once per session.
    /// </summary>
    public sealed class DnsResolverService
    {
        private readonly ConcurrentDictionary<string, string?> results = new();
        private readonly ConcurrentDictionary<string, byte> requested = new();
        private readonly SemaphoreSlim throttle = new(8);

        public void Request(string ip)
        {
            if (requested.TryAdd(ip, 0))
                _ = ResolveAsync(ip);
        }

        /// <summary>True once the lookup has finished; name is null if the IP has no host name.</summary>
        public bool TryGet(string ip, out string? name) => results.TryGetValue(ip, out name);

        private async Task ResolveAsync(string ip)
        {
            await throttle.WaitAsync();
            try
            {
                var lookup = Dns.GetHostEntryAsync(IPAddress.Parse(ip));
                var finished = await Task.WhenAny(lookup, Task.Delay(4000));
                string? name = null;
                if (finished == lookup && lookup.Status == TaskStatus.RanToCompletion)
                {
                    string host = lookup.Result.HostName;
                    if (!string.IsNullOrEmpty(host) && host != ip) name = host;
                }
                else
                {
                    // Observe a late failure so it is not reported as unobserved
                    _ = lookup.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                }
                results[ip] = name;
            }
            catch
            {
                results[ip] = null;
            }
            finally
            {
                throttle.Release();
            }
        }
    }

    /// <summary>
    /// Owner and location lookups via ip-api.com (free, no key). Batches up to 100 IPs per request
    /// and stays under the free limit of 15 batch requests a minute.
    /// </summary>
    public sealed class IpInfoService
    {
        private const string Fields = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,proxy,hosting,query";

        private readonly HttpClient http;
        private readonly ConcurrentDictionary<string, GeoInfo> cache = new();
        private readonly ConcurrentDictionary<string, byte> requested = new();
        private readonly ConcurrentQueue<string> pending = new();

        public IpInfoService(HttpClient http)
        {
            this.http = http;
            _ = Task.Run(BatchLoopAsync);
        }

        public bool Enabled { get; set; } = true;

        public void Request(string ip)
        {
            if (Enabled && requested.TryAdd(ip, 0))
                pending.Enqueue(ip);
        }

        public bool TryGet(string ip, [NotNullWhen(true)] out GeoInfo? info) => cache.TryGetValue(ip, out info);

        private async Task BatchLoopAsync()
        {
            while (true)
            {
                await Task.Delay(4500);
                if (!Enabled || pending.IsEmpty) continue;

                var batch = new List<string>();
                while (batch.Count < 100 && pending.TryDequeue(out var ip))
                    batch.Add(ip);

                try
                {
                    using var content = new StringContent(JsonSerializer.Serialize(batch), Encoding.UTF8, "application/json");
                    using var response = await http.PostAsync($"http://ip-api.com/batch?fields={Fields}", content);
                    if ((int)response.StatusCode == 429)
                    {
                        Requeue(batch);
                        await Task.Delay(60_000);
                        continue;
                    }
                    response.EnsureSuccessStatusCode();

                    using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    foreach (var element in doc.RootElement.EnumerateArray())
                    {
                        var info = Parse(element);
                        if (info.Ip.Length > 0) cache[info.Ip] = info;
                    }
                }
                catch
                {
                    // Offline or service down - try this batch again later
                    Requeue(batch);
                    await Task.Delay(30_000);
                }
            }
        }

        private void Requeue(List<string> batch)
        {
            foreach (var ip in batch) pending.Enqueue(ip);
        }

        /// <summary>Immediate lookup for one IP. Pass null to look up this PC's own public address.</summary>
        public async Task<GeoInfo?> LookupNowAsync(string? ip)
        {
            if (ip != null && cache.TryGetValue(ip, out var cached)) return cached;
            try
            {
                string json = await http.GetStringAsync($"http://ip-api.com/json/{ip}?fields={Fields}");
                using var doc = JsonDocument.Parse(json);
                var info = Parse(doc.RootElement);
                if (ip != null) cache[ip] = info;
                return info;
            }
            catch
            {
                return null;
            }
        }

        private static GeoInfo Parse(JsonElement e)
        {
            string? Str(string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            double Num(string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;
            bool Flag(string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

            // "as" looks like "AS15169 Google LLC"
            int asNumber = 0;
            string? asText = Str("as");
            if (asText != null && asText.StartsWith("AS", StringComparison.Ordinal))
            {
                string digits = new string(asText.Skip(2).TakeWhile(char.IsDigit).ToArray());
                int.TryParse(digits, out asNumber);
            }

            return new GeoInfo
            {
                Ip = Str("query") ?? "",
                Success = Str("status") == "success",
                Country = Str("country"),
                CountryCode = Str("countryCode"),
                Region = Str("regionName"),
                City = Str("city"),
                Lat = Num("lat"),
                Lon = Num("lon"),
                Isp = Str("isp"),
                Org = Str("org"),
                AsNumber = asNumber,
                AsName = Str("asname"),
                Proxy = Flag("proxy"),
                Hosting = Flag("hosting")
            };
        }
    }
}
