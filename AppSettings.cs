using System.IO;
using System.Text.Json;

namespace WinEtherCloneApe
{
    /// <summary>
    /// User settings, stored as JSON in %LOCALAPPDATA%\WinEtherCloneApe\settings.json
    /// </summary>
    public class AppSettings
    {
        public string? LastAdapterName { get; set; }
        public string? ZenmapPath { get; set; }
        public bool OnlineLookups { get; set; } = true;

        public static string DataFolder { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinEtherCloneApe");

        private static string FilePath => Path.Combine(DataFolder, "settings.json");

        public static AppSettings Load()
        {
            try
            {
                if (File.Exists(FilePath))
                    return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
            }
            catch
            {
                // Corrupt settings file - fall back to defaults
            }
            return new AppSettings();
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(DataFolder);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch
            {
                // Settings are a convenience; never crash over them
            }
        }
    }
}
