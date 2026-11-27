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
        /// </summary>
        [STAThread]
        public static int Main(string[] args)
        {
            int hostIndex = Array.IndexOf(args, "--capture-host");
            string? captureHost = hostIndex >= 0 && hostIndex + 1 < args.Length ? args[hostIndex + 1] : null;

            var app = new App();
            var window = new MainWindow(
                demoMode: args.Contains("--demo"),
                demoOpenMap: args.Contains("--open-map"),
                captureHost: captureHost);
            return app.Run(window);
        }
    }
}
