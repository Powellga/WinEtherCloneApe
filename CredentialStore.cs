using System.Runtime.InteropServices;
using System.Text;

namespace WinEtherCloneApe
{
    /// <summary>
    /// Saves passwords in Windows Credential Manager (generic credentials, this user only),
    /// so they never sit in the settings file. Visible under Control Panel, Credential Manager,
    /// Windows Credentials, as "WinEtherCloneApe:...".
    /// </summary>
    public static class CredentialStore
    {
        private const int CredTypeGeneric = 1;
        private const int CredPersistLocalMachine = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public string TargetName;
            public string? Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string? TargetAlias;
            public string? UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CredWriteW")]
        private static extern bool CredWrite(ref CREDENTIAL credential, int flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CredReadW")]
        private static extern bool CredRead(string target, int type, int flags, out IntPtr credential);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CredDeleteW")]
        private static extern bool CredDelete(string target, int type, int flags);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr buffer);

        public static string RouterTarget(string user, string host, int port) => $"WinEtherCloneApe:ssh:{user}@{host}:{port}";

        public static void Save(string target, string user, string password)
        {
            byte[] blob = Encoding.Unicode.GetBytes(password);
            IntPtr buffer = Marshal.AllocHGlobal(blob.Length);
            try
            {
                Marshal.Copy(blob, 0, buffer, blob.Length);
                var credential = new CREDENTIAL
                {
                    Type = CredTypeGeneric,
                    TargetName = target,
                    UserName = user,
                    CredentialBlob = buffer,
                    CredentialBlobSize = blob.Length,
                    Persist = CredPersistLocalMachine
                };
                if (!CredWrite(ref credential, 0))
                    throw new InvalidOperationException($"Windows Credential Manager refused the password (error {Marshal.GetLastWin32Error()}).");
            }
            finally
            {
                Array.Clear(blob);
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static string? Load(string target)
        {
            if (!CredRead(target, CredTypeGeneric, 0, out IntPtr pointer)) return null;
            try
            {
                var credential = Marshal.PtrToStructure<CREDENTIAL>(pointer);
                if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0) return null;
                return Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
            }
            finally
            {
                CredFree(pointer);
            }
        }

        public static void Delete(string target) => CredDelete(target, CredTypeGeneric, 0);
    }
}
