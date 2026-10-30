using System.Diagnostics;
using System.IO;

namespace WinEtherCloneApe
{
    /// <summary>
    /// Launches Zenmap and web pages.
    /// </summary>
    public static class ExternalTools
    {
        /// <summary>Zenmap profiles that ship with Nmap, in menu order.</summary>
        public static readonly string[] ZenmapProfiles =
        {
            "Quick scan",
            "Quick scan plus",
            "Regular scan",
            "Intense scan",
            "Ping scan",
            "Quick traceroute",
        };

        public static string? FindZenmap(string? configuredPath)
        {
            var candidates = new[]
            {
                configuredPath,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Nmap", "zenmap.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Nmap", "zenmap.exe"),
            };
            return candidates.FirstOrDefault(p => !string.IsNullOrEmpty(p) && File.Exists(p));
        }

        /// <summary>Opens Zenmap with the target filled in and starts the chosen profile's scan.</summary>
        public static void LaunchZenmap(string zenmapPath, string target, string profile)
        {
            var psi = new ProcessStartInfo(zenmapPath)
            {
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(zenmapPath) ?? ""
            };
            psi.ArgumentList.Add("-t");
            psi.ArgumentList.Add(target);
            psi.ArgumentList.Add("-p");
            psi.ArgumentList.Add(profile);
            Process.Start(psi);
        }

        /// <summary>
        /// Opens a URL in the default browser. Goes through explorer.exe so the browser
        /// does not inherit this app's administrator rights.
        /// </summary>
        public static void OpenUrl(string url)
        {
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { url }, UseShellExecute = false });
        }
    }
}
