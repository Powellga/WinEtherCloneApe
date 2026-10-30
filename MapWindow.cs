using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace WinEtherCloneApe
{
    public sealed class MapPoint
    {
        public double Lat { get; set; }
        public double Lon { get; set; }
        public string Title { get; set; } = "";
        public List<string> Lines { get; set; } = new();
        public string Color { get; set; } = "#ffffff";
        public bool Threat { get; set; }
    }

    /// <summary>
    /// Shows hosts on a dark world map (Leaflet + CARTO tiles inside WebView2).
    /// The green dot is this network's own public location.
    /// </summary>
    public sealed class MapWindow : Window
    {
        private const string HostName = "winetherape.map";
        private readonly WebView2 web = new();

        public MapWindow(string title, MapPoint? home, IList<MapPoint> points)
        {
            Title = title;
            Width = 1100;
            Height = 720;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(Color.FromRgb(10, 10, 20));
            Content = web;
            Loaded += async (_, _) => await ShowMapAsync(home, points);
        }

        private async Task ShowMapAsync(MapPoint? home, IList<MapPoint> points)
        {
            string folder = Path.Combine(AppSettings.DataFolder, "map");
            string fileName = $"map-{Guid.NewGuid():N}.html";
            try
            {
                Directory.CreateDirectory(folder);
                foreach (var old in Directory.GetFiles(folder, "map-*.html"))
                {
                    if (DateTime.Now - File.GetLastWriteTime(old) > TimeSpan.FromHours(1))
                        File.Delete(old);
                }
                await File.WriteAllTextAsync(Path.Combine(folder, fileName), BuildHtml(home, points));

                var env = await CoreWebView2Environment.CreateAsync(null, Path.Combine(AppSettings.DataFolder, "WebView2"));
                await web.EnsureCoreWebView2Async(env);
                web.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
                web.CoreWebView2.Settings.AreDevToolsEnabled = false;
                web.CoreWebView2.SetVirtualHostNameToFolderMapping(HostName, folder, CoreWebView2HostResourceAccessKind.Allow);
                web.CoreWebView2.Navigate($"https://{HostName}/{fileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"The map could not be shown inside the app ({ex.Message}).\n\nOpening it in your browser instead.",
                    "Map", MessageBoxButton.OK, MessageBoxImage.Information);
                var first = points.FirstOrDefault() ?? home;
                if (first != null)
                    ExternalTools.OpenUrl($"https://www.openstreetmap.org/?mlat={first.Lat}&mlon={first.Lon}#map=6/{first.Lat}/{first.Lon}");
                Close();
            }
        }

        private static string BuildHtml(MapPoint? home, IList<MapPoint> points)
        {
            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            string data = JsonSerializer.Serialize(new { home, points }, options);

            return """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  html, body, #map { height: 100%; margin: 0; background: #0a0a14; }
  .leaflet-popup-content { font: 13px "Segoe UI", sans-serif; line-height: 1.45; }
  .leaflet-popup-content b { font-size: 14px; }
  .threat { color: #ff1744; font-weight: bold; }
</style>
</head>
<body>
<div id="map"></div>
<script>
const data = __DATA__;
const map = L.map('map', { worldCopyJump: true });
const esri = 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/';
L.tileLayer(esri + 'World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
  attribution: 'Tiles &copy; Esri, HERE, Garmin, &copy; OpenStreetMap contributors', maxZoom: 16
}).addTo(map);
L.tileLayer(esri + 'World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', { maxZoom: 16 }).addTo(map);

function popup(p) {
  const div = document.createElement('div');
  const title = document.createElement('b');
  title.textContent = p.title;
  div.appendChild(title);
  for (const line of p.lines) {
    const row = document.createElement('div');
    row.textContent = line;
    if (line.startsWith('THREAT')) row.className = 'threat';
    div.appendChild(row);
  }
  return div;
}

const bounds = [];
if (data.home) {
  const h = data.home;
  L.circleMarker([h.lat, h.lon], { radius: 8, color: '#ffffff', weight: 2, fillColor: '#32cd32', fillOpacity: 1 })
    .addTo(map).bindPopup(popup(h));
  bounds.push([h.lat, h.lon]);
}
for (const p of data.points) {
  if (data.home) {
    L.polyline([[data.home.lat, data.home.lon], [p.lat, p.lon]],
      { color: p.threat ? '#ff1744' : p.color, weight: p.threat ? 2 : 1, opacity: 0.55 }).addTo(map);
  }
  const m = L.circleMarker([p.lat, p.lon], {
    radius: p.threat ? 11 : 7, color: p.threat ? '#ff1744' : '#ffffff', weight: 2, fillColor: p.color, fillOpacity: 0.9
  }).addTo(map).bindPopup(popup(p));
  bounds.push([p.lat, p.lon]);
  if (data.points.length === 1) setTimeout(() => m.openPopup(), 300);
}
if (bounds.length === 1) map.setView(bounds[0], 6);
else if (bounds.length > 1) map.fitBounds(bounds, { padding: [50, 50], maxZoom: 8 });
else map.setView([20, 0], 2);
</script>
</body>
</html>
""".Replace("__DATA__", data);
        }
    }
}
