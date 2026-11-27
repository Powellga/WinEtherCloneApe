using Microsoft.Win32;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace WinEtherCloneApe
{
    /// <summary>One line of the threat report.</summary>
    public sealed class ThreatRow
    {
        public string Type { get; init; } = "";
        public string Indicator { get; init; } = "";
        public string HostName { get; init; } = "";
        public string Lists { get; init; } = "";
        public string YourDevices { get; init; } = "";
        public string StartedBy { get; init; } = "";
        public string Ports { get; init; } = "";
        public string Traffic { get; init; } = "";
        public string FirstSeen { get; init; } = "";
        public string LastSeen { get; init; } = "";
        public string Notes { get; init; } = "";
        public DateTime Sort { get; init; }
    }

    /// <summary>
    /// Every threat found this session, with what is needed to act on it: which of your devices
    /// talked to it, who started the conversation, ports, traffic and timing. Also states how
    /// much was checked, so a clean report can be trusted.
    /// </summary>
    public class ThreatReportWindow : Window
    {
        private readonly ThreatMonitor monitor;
        private readonly ThreatIntel intel;
        private readonly Func<string> captureState;
        private readonly DataGrid grid;
        private readonly TextBlock summary;
        private readonly DispatcherTimer refreshTimer;
        private int lastCount = -1;
        private int ticksSinceRebuild;

        public ThreatReportWindow(ThreatMonitor monitor, ThreatIntel intel, Func<string> captureState)
        {
            this.monitor = monitor;
            this.intel = intel;
            this.captureState = captureState;

            Title = "Threat report";
            Width = 1250;
            Height = 600;
            Icon = MainWindow.AppIcon;
            Background = new SolidColorBrush(Color.FromRgb(30, 30, 40));

            var root = new DockPanel();

            var toolbar = new WrapPanel { Background = new SolidColorBrush(Color.FromRgb(45, 45, 55)) };
            toolbar.Children.Add(Button("Export CSV...", Colors.SteelBlue, ExportCsv));
            toolbar.Children.Add(Button("Check selected on AbuseIPDB", Colors.DarkSlateBlue, CheckSelected));
            toolbar.Children.Add(Button("Copy selected", Colors.DimGray, CopySelected));
            toolbar.Children.Add(Button("Open log folder", Colors.DimGray,
                () => ExternalTools.OpenUrl(AppSettings.DataFolder)));
            DockPanel.SetDock(toolbar, Dock.Top);
            root.Children.Add(toolbar);

            summary = new TextBlock
            {
                Foreground = Brushes.Gainsboro,
                Margin = new Thickness(10, 8, 10, 8),
                TextWrapping = TextWrapping.Wrap
            };
            DockPanel.SetDock(summary, Dock.Top);
            root.Children.Add(summary);

            grid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                CanUserAddRows = false,
                SelectionMode = DataGridSelectionMode.Extended,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                Background = new SolidColorBrush(Color.FromRgb(20, 20, 28)),
                RowBackground = new SolidColorBrush(Color.FromRgb(28, 28, 38)),
                AlternatingRowBackground = new SolidColorBrush(Color.FromRgb(34, 34, 46)),
                Foreground = Brushes.Gainsboro,
                GridLinesVisibility = DataGridGridLinesVisibility.None,
                FontSize = 12
            };
            var headerStyle = new Style(typeof(System.Windows.Controls.Primitives.DataGridColumnHeader));
            headerStyle.Setters.Add(new Setter(BackgroundProperty, new SolidColorBrush(Color.FromRgb(50, 50, 64))));
            headerStyle.Setters.Add(new Setter(ForegroundProperty, Brushes.White));
            headerStyle.Setters.Add(new Setter(FontWeightProperty, FontWeights.SemiBold));
            headerStyle.Setters.Add(new Setter(PaddingProperty, new Thickness(6, 4, 6, 4)));
            headerStyle.Setters.Add(new Setter(BorderBrushProperty, new SolidColorBrush(Color.FromRgb(70, 70, 90))));
            headerStyle.Setters.Add(new Setter(BorderThicknessProperty, new Thickness(0, 0, 1, 1)));
            grid.ColumnHeaderStyle = headerStyle;

            AddColumn("Type", nameof(ThreatRow.Type), 80);
            AddColumn("Address or domain", nameof(ThreatRow.Indicator), 170);
            AddColumn("Host name", nameof(ThreatRow.HostName), 160);
            AddColumn("Listed on", nameof(ThreatRow.Lists), 200);
            AddColumn("Your devices", nameof(ThreatRow.YourDevices), 130);
            AddColumn("Started by", nameof(ThreatRow.StartedBy), 105);
            AddColumn("Ports", nameof(ThreatRow.Ports), 80);
            AddColumn("Traffic", nameof(ThreatRow.Traffic), 120);
            AddColumn("First seen", nameof(ThreatRow.FirstSeen), 75);
            AddColumn("Last seen", nameof(ThreatRow.LastSeen), 75);
            AddColumn("Notes", nameof(ThreatRow.Notes), 260);
            root.Children.Add(grid);

            Content = root;

            refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            refreshTimer.Tick += (_, _) => Refresh();
            refreshTimer.Start();
            Closed += (_, _) => refreshTimer.Stop();
            Refresh();
        }

        private static Button Button(string text, Color color, Action click)
        {
            var b = new Button
            {
                Content = text,
                Padding = new Thickness(12, 4, 12, 4),
                Margin = new Thickness(6),
                Background = new SolidColorBrush(color),
                Foreground = Brushes.White
            };
            b.Click += (_, _) => click();
            return b;
        }

        private void AddColumn(string header, string property, double width) =>
            grid.Columns.Add(new DataGridTextColumn
            {
                Header = header,
                Binding = new System.Windows.Data.Binding(property),
                Width = width
            });

        private void Refresh()
        {
            string lists = intel.LoadedFeeds == 0
                ? "NO THREAT LISTS LOADED - nothing can be checked until they download."
                : $"{intel.LoadedFeeds} of {ThreatIntel.Feeds.Length} threat lists loaded ({intel.Ipv4Ranges:N0} IPv4 ranges, " +
                  $"{intel.Ipv6Ranges:N0} IPv6 ranges, {intel.DomainCount:N0} domains).";
            if (intel.Failures.Count > 0) lists += $" Could not refresh: {string.Join(", ", intel.Failures)}.";

            summary.Text =
                $"Checked this session: {monitor.AddressesChecked:N0} internet addresses ({monitor.Ipv4Checked:N0} IPv4, " +
                $"{monitor.Ipv6Checked:N0} IPv6) and {monitor.NamesChecked:N0} DNS names. Every one is re-checked whenever the lists update " +
                $"(last re-check {monitor.LastRecheck:t}).\n{lists}\n{captureState()}\n" +
                $"Threats found: {monitor.ThreatCount}. Full log: {Path.Combine(AppSettings.DataFolder, "threats.log")}";

            // Rebuild when a threat is added, and every 10 seconds for fresh traffic numbers
            int count = monitor.ThreatCount;
            if (count == lastCount && ++ticksSinceRebuild < 5) return;
            ticksSinceRebuild = 0;
            lastCount = count;
            var rows = BuildRows();

            var selected = grid.SelectedItems.Cast<ThreatRow>().Select(r => r.Indicator).ToHashSet();
            grid.ItemsSource = rows;
            foreach (var row in rows.Where(r => selected.Contains(r.Indicator))) grid.SelectedItems.Add(row);
        }

        private List<ThreatRow> BuildRows()
        {
            var rows = monitor.ThreatHosts.Select(h => new ThreatRow
            {
                Type = "Address",
                Indicator = h.Ip,
                HostName = h.HostName ?? string.Join(", ", h.DnsNames),
                Lists = string.Join(", ", h.Threat!.Feeds.Select(f => f.Name)),
                YourDevices = string.Join(", ", h.LocalDevices),
                StartedBy = h.StartedBy ?? "",
                Ports = string.Join(", ", h.Ports),
                Traffic = h.Packets > 0 ? $"{h.Packets:N0} pkts, {MainWindow.FormatBytes(h.Bytes)}" : "looked up only",
                FirstSeen = h.FirstSeen.ToString("T"),
                LastSeen = h.LastSeen.ToString("T"),
                Notes = (h.Threat.ViaDomain != null ? $"Resolved from listed domain {h.Threat.ViaDomain}. " : "") +
                        (h.DetectedLater ? $"Matched after a list update (detected {h.DetectedAt:T})." : ""),
                Sort = h.DetectedAt ?? h.FirstSeen
            }).Concat(monitor.DnsThreats.Select(d => new ThreatRow
            {
                Type = "DNS lookup",
                Indicator = d.Domain,
                Lists = string.Join(", ", d.Match.Feeds.Select(f => f.Name)),
                YourDevices = string.Join(", ", d.Devices),
                StartedBy = "Your device",
                Ports = "53",
                Traffic = $"{d.Lookups:N0} lookups",
                FirstSeen = d.FirstSeen.ToString("T"),
                LastSeen = d.LastSeen.ToString("T"),
                Notes = (d.Match.Indicator != d.Domain ? $"Parent domain {d.Match.Indicator} is listed. " : "") +
                        (d.ResolvedTo.Count > 0 ? $"Resolved to {string.Join(", ", d.ResolvedTo)}." : ""),
                Sort = d.FirstSeen
            }));
            return rows.OrderByDescending(r => r.Sort).ToList();
        }

        private void ExportCsv()
        {
            var dialog = new SaveFileDialog
            {
                Title = "Export threat report",
                FileName = $"threat_report_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                Filter = "CSV (*.csv)|*.csv",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            };
            if (dialog.ShowDialog(this) != true) return;
            try
            {
                monitor.ExportCsv(dialog.FileName);
                ExternalTools.ShowInFolder(dialog.FileName);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not export: {ex.Message}", "Threat report", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CheckSelected()
        {
            foreach (var row in grid.SelectedItems.Cast<ThreatRow>().Take(5))
            {
                string url = row.Type == "Address"
                    ? $"https://www.abuseipdb.com/check/{row.Indicator}"
                    : $"https://www.virustotal.com/gui/domain/{row.Indicator}";
                ExternalTools.OpenUrl(url);
            }
        }

        private void CopySelected()
        {
            var lines = grid.SelectedItems.Cast<ThreatRow>().Select(r =>
                $"{r.Type}\t{r.Indicator}\t{r.HostName}\t{r.Lists}\t{r.YourDevices}\t{r.StartedBy}\t{r.Ports}\t{r.Traffic}\t{r.FirstSeen}\t{r.LastSeen}\t{r.Notes}");
            string text = string.Join(Environment.NewLine, lines);
            if (text.Length > 0) Clipboard.SetText(text);
        }
    }
}
