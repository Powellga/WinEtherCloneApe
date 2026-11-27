using System.Diagnostics;
using System.IO;

namespace WinEtherCloneApe
{
    /// <summary>Flashes the app's taskbar button until it is clicked (used for threat alerts).</summary>
    public static class TaskbarFlash
    {
        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct FLASHWINFO
        {
            public uint cbSize;
            public IntPtr hwnd;
            public uint dwFlags;
            public uint uCount;
            public uint dwTimeout;
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool FlashWindowEx(ref FLASHWINFO info);

        public static void Flash(System.Windows.Window window)
        {
            try
            {
                var hwnd = new System.Windows.Interop.WindowInteropHelper(window).Handle;
                if (hwnd == IntPtr.Zero || window.IsActive) return;
                var info = new FLASHWINFO
                {
                    cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<FLASHWINFO>(),
                    hwnd = hwnd,
                    dwFlags = 0x3 | 0xC, // FLASHW_ALL | FLASHW_TIMERNOFG
                };
                FlashWindowEx(ref info);
            }
            catch
            {
                // Cosmetic only
            }
        }
    }

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
        /// Opens a URL in the default browser (or a file in its default program). Goes through
        /// explorer.exe so the browser does not inherit this app's administrator rights.
        /// </summary>
        public static void OpenUrl(string url)
        {
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { url }, UseShellExecute = false });
        }

        /// <summary>Shows a file selected in File Explorer.</summary>
        public static void ShowInFolder(string path)
        {
            Process.Start(new ProcessStartInfo("explorer.exe") { Arguments = $"/select,\"{path}\"", UseShellExecute = false });
        }

        /// <summary>Builds http://ip/ or https://ip:port/, with brackets around IPv6 addresses.</summary>
        public static string WebUrl(string ip, bool https, int port)
        {
            string host = ip.Contains(':') ? $"[{ip}]" : ip;
            bool defaultPort = https ? port == 443 : port == 80;
            return $"{(https ? "https" : "http")}://{host}{(defaultPort ? "" : ":" + port)}/";
        }

        /// <summary>The OpenSSH client that ships with Windows 10 and 11.</summary>
        public static string? FindSsh()
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh.exe");
            return File.Exists(path) ? path : null;
        }

        /// <summary>A user name ssh accepts, with nothing a shell or Windows Terminal would treat as a command.</summary>
        public static bool IsSafeUserName(string user) =>
            user.Length is > 0 and <= 64 && user.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '@' or '\\');

        /// <summary>Opens an SSH session in Windows Terminal, or a console window when Windows Terminal is not installed.</summary>
        public static void LaunchSsh(string sshPath, string user, string ip, int port)
        {
            string target = $"{user}@{ip}";
            string wt = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WindowsApps", "wt.exe");

            if (File.Exists(wt))
            {
                try
                {
                    var psi = new ProcessStartInfo(wt) { UseShellExecute = false };
                    foreach (var arg in new[] { "new-tab", "--title", $"SSH {target}", sshPath, "-p", port.ToString(), target })
                        psi.ArgumentList.Add(arg);
                    Process.Start(psi);
                    return;
                }
                catch
                {
                    // Fall through to a plain console window
                }
            }

            // cmd /k keeps the window open, so a refused connection's error stays readable
            Process.Start(new ProcessStartInfo("cmd.exe")
            {
                Arguments = $"/k \"\"{sshPath}\" -p {port} {target}\"",
                UseShellExecute = true
            });
        }
    }
}
