using System.Windows;

namespace WinEtherCloneApe
{
    public class App : Application
    {
        /// <summary>
        /// Command line options:
        ///   --demo               feed simulated traffic instead of capturing (no adapter needed)
        ///   --open-map           with --demo, open the world map after 20 seconds
        ///   --capture-host <ip>  start capturing on the last-used adapter and open a packet capture for that address
        ///   --zoom <factor>      start zoomed in (for example 3), centered on the view
        ///   --isolate <ip|busiest> isolate a host after 15 seconds (testing the Isolate view)
        ///   --replay-pcap <file> feed a .pcap file through the same reader used for capture from the router (testing)
        /// </summary>
        [STAThread]
        public static int Main(string[] args)
        {
            int hostIndex = Array.IndexOf(args, "--capture-host");
            string? captureHost = hostIndex >= 0 && hostIndex + 1 < args.Length ? args[hostIndex + 1] : null;

            int zoomIndex = Array.IndexOf(args, "--zoom");
            double startZoom = zoomIndex >= 0 && zoomIndex + 1 < args.Length
                && double.TryParse(args[zoomIndex + 1], System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out double z) ? z : 1;

            int replayIndex = Array.IndexOf(args, "--replay-pcap");
            string? replayPcap = replayIndex >= 0 && replayIndex + 1 < args.Length ? args[replayIndex + 1] : null;

            int isolateIndex = Array.IndexOf(args, "--isolate");
            string? isolate = isolateIndex >= 0 && isolateIndex + 1 < args.Length ? args[isolateIndex + 1] : null;

            var app = new App();
            var window = new MainWindow(
                demoMode: args.Contains("--demo"),
                demoOpenMap: args.Contains("--open-map"),
                captureHost: captureHost,
                startZoom: startZoom,
                replayPcap: replayPcap,
                isolate: isolate);
            return app.Run(window);
        }
    }
}
