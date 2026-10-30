using System.Windows;

namespace WinEtherCloneApe
{
    public class App : Application
    {
        /// <summary>
        /// Command line options (for testing):
        ///   --demo      feed simulated traffic instead of capturing (no adapter needed)
        ///   --open-map  with --demo, open the world map after 20 seconds
        /// </summary>
        [STAThread]
        public static int Main(string[] args)
        {
            var app = new App();
            var window = new MainWindow(
                demoMode: args.Contains("--demo"),
                demoOpenMap: args.Contains("--open-map"));
            return app.Run(window);
        }
    }
}
