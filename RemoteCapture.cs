using PacketDotNet;
using Renci.SshNet;
using Renci.SshNet.Common;
using SharpPcap;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Windows;

namespace WinEtherCloneApe
{
    /// <summary>
    /// Reads the classic pcap format from a stream, such as "tcpdump -w -" arriving over SSH.
    /// Each packet is handed over with its original length (the router may send only the first bytes).
    /// </summary>
    public static class PcapStreamReader
    {
        private const int MaxPacket = 262_144;

        public static void ReadAll(Stream stream, Action<RawCapture, int> onPacket, CancellationToken token)
        {
            var header = new byte[24];
            if (!ReadFully(stream, header, token))
                throw new EndOfStreamException("The router sent no capture data.");

            uint magic = BitConverter.ToUInt32(header, 0);
            (bool swap, bool nano) = magic switch
            {
                0xa1b2c3d4 => (false, false),
                0xd4c3b2a1 => (true, false),
                0xa1b23c4d => (false, true),
                0x4d3cb2a1 => (true, true),
                _ => throw new InvalidDataException("The router did not send pcap data. Is tcpdump installed there?")
            };
            var linkType = (LinkLayers)(Read32(header, 20, swap) & 0x0FFF_FFFF); // high bits can carry FCS flags

            var record = new byte[16];
            while (!token.IsCancellationRequested && ReadFully(stream, record, token))
            {
                uint seconds = Read32(record, 0, swap);
                uint fraction = Read32(record, 4, swap);
                uint included = Read32(record, 8, swap);
                uint original = Read32(record, 12, swap);
                if (included > MaxPacket) throw new InvalidDataException($"Corrupt capture data (packet of {included:N0} bytes).");

                var data = new byte[included];
                if (!ReadFully(stream, data, token)) break;
                ulong micro = nano ? fraction / 1000 : fraction;
                var raw = new RawCapture(linkType, new PosixTimeval(seconds, micro), data);
                onPacket(raw, (int)Math.Max(original, included));
            }
        }

        private static uint Read32(byte[] buffer, int offset, bool swap)
        {
            uint value = BitConverter.ToUInt32(buffer, offset);
            return swap ? System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(value) : value;
        }

        private static bool ReadFully(Stream stream, byte[] buffer, CancellationToken token)
        {
            int done = 0;
            while (done < buffer.Length)
            {
                if (token.IsCancellationRequested) return false;
                int n = stream.Read(buffer, done, buffer.Length - done);
                if (n <= 0) return false;
                done += n;
            }
            return true;
        }
    }

    /// <summary>
    /// Captures on a UniFi gateway (or any Linux router with tcpdump) by running tcpdump over SSH
    /// and streaming the packets back. Nothing is installed on the router. The router's SSH host key
    /// is pinned on first use, so a different device answering at the router's address is refused.
    /// </summary>
    public sealed class RemoteCaptureSession : IDisposable
    {
        private static readonly Regex InterfacePattern = new("^[A-Za-z0-9._-]{1,15}$");
        private static readonly Regex HostPattern = new("^[A-Za-z0-9.:-]{1,253}$");

        private readonly string host;
        private readonly int port;
        private readonly string user;
        private readonly string password;
        private readonly AppSettings settings;
        private readonly Window owner;
        private readonly CancellationTokenSource cancel = new();
        private readonly List<SshCommand> commands = new();
        private SshClient? client;
        private string? hostKeyProblem;
        private int activeInterfaces;
        private readonly string token = Guid.NewGuid().ToString("N")[..12];

        public string Host => host;
        public IReadOnlyList<string> Interfaces { get; private set; } = Array.Empty<string>();
        public int ActiveInterfaces => Volatile.Read(ref activeInterfaces);

        /// <summary>Raised on a background thread when one interface's capture ends, with the reason.</summary>
        public event Action<string, string>? InterfaceStopped;

        public RemoteCaptureSession(string host, int port, string user, string password, AppSettings settings, Window owner)
        {
            this.host = host;
            this.port = port;
            this.user = user;
            this.password = password;
            this.settings = settings;
            this.owner = owner;
        }

        public static bool IsValidInterface(string name) => InterfacePattern.IsMatch(name);
        public static bool IsValidHost(string name) => HostPattern.IsMatch(name);

        public static List<string> ParseInterfaces(string text) =>
            text.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal).ToList();

        private string KeyId => $"{host}:{port}";

        /// <summary>Connects and logs in. Blocking: call from a background thread.</summary>
        public void Connect()
        {
            if (!IsValidHost(host)) throw new ArgumentException("The router address is not valid.");

            var passwordAuth = new PasswordAuthenticationMethod(user, password);
            var keyboardAuth = new KeyboardInteractiveAuthenticationMethod(user);
            keyboardAuth.AuthenticationPrompt += (_, e) =>
            {
                foreach (var prompt in e.Prompts) prompt.Response = password;
            };
            var info = new ConnectionInfo(host, port, user, passwordAuth, keyboardAuth)
            {
                Timeout = TimeSpan.FromSeconds(10)
            };

            client = new SshClient(info) { KeepAliveInterval = TimeSpan.FromSeconds(20) };
            client.HostKeyReceived += OnHostKeyReceived;
            try
            {
                client.Connect();
            }
            catch (SshAuthenticationException)
            {
                throw new InvalidOperationException($"The router refused the user name or password for {user}@{host}.");
            }
            catch (SshConnectionException) when (hostKeyProblem != null)
            {
                throw new InvalidOperationException(hostKeyProblem);
            }
            catch (SocketException ex)
            {
                throw new InvalidOperationException(
                    $"Could not reach SSH on {host} port {port} ({ex.Message}).\n\n" +
                    "Check that SSH is turned on in UniFi OS (Settings, Control Plane, Console) and that the " +
                    "router's firewall allows SSH from this PC.");
            }
            catch (SshOperationTimeoutException)
            {
                throw new InvalidOperationException($"The router at {host} did not answer in time.");
            }
            if (hostKeyProblem != null) throw new InvalidOperationException(hostKeyProblem);
        }

        private void OnHostKeyReceived(object? sender, HostKeyEventArgs e)
        {
            string fingerprint = "SHA256:" + e.FingerPrintSHA256;
            string? known = null;
            owner.Dispatcher.Invoke(() => settings.RouterHostKeys.TryGetValue(KeyId, out known));

            if (known != null)
            {
                e.CanTrust = string.Equals(known, fingerprint, StringComparison.Ordinal);
                if (!e.CanTrust)
                    hostKeyProblem =
                        $"Connection refused: the router's identity key has changed.\n\nExpected {known}\nReceived {fingerprint}\n\n" +
                        "This happens after a router reset, replacement or some firmware updates, but it can also mean another " +
                        "device is pretending to be the router. If you know why it changed, open the router settings and press " +
                        "\"Forget saved router key\", then connect again.";
                return;
            }

            bool trust = owner.Dispatcher.Invoke(() => MessageBox.Show(owner,
                $"First connection to {host}.\n\nThe router identified itself with this {e.HostKeyName} key:\n{fingerprint}\n\n" +
                "Trust this router? Its key will be remembered, and the app will refuse to connect if it ever changes.",
                "Trust router", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes);

            e.CanTrust = trust;
            if (trust)
            {
                owner.Dispatcher.Invoke(() =>
                {
                    settings.RouterHostKeys[KeyId] = fingerprint;
                    settings.Save();
                });
            }
            else
            {
                hostKeyProblem = "Connection cancelled: the router's key was not trusted.";
            }
        }

        /// <summary>Lists the router's network interfaces with their IPv4 addresses (after Connect).</summary>
        public string ListInterfaces()
        {
            using var command = client!.CreateCommand("ip -br -4 addr show 2>/dev/null || ip -4 addr show");
            command.CommandTimeout = TimeSpan.FromSeconds(10);
            return command.Execute();
        }

        /// <summary>Starts tcpdump on each interface (after Connect). Packets arrive on background threads.</summary>
        public void Start(IReadOnlyList<string> interfaces, int snapLength, Action<RawCapture, int> onPacket)
        {
            if (interfaces.Count == 0) throw new ArgumentException("Enter at least one router interface, such as br0.");
            foreach (var name in interfaces)
                if (!IsValidInterface(name)) throw new ArgumentException($"\"{name}\" is not a valid interface name.");

            Interfaces = interfaces;
            snapLength = Math.Clamp(snapLength, 96, 65535);

            foreach (var name in interfaces)
            {
                // Leave out this app's own SSH connection, or the capture would feed on itself. The router's shell
                // knows its exact addresses and ports from SSH_CONNECTION ("client port server port").
                string tcpdump = $"exec tcpdump -i {name} -U -n -s {snapLength} -w -";
                // The process ID goes in /tmp so Stop can end tcpdump at once (otherwise it lingers until its next write fails)
                string script = $"echo $$ > /tmp/wecape-{token}-{name}.pid; " +
                                "set -- $SSH_CONNECTION; if [ $# -ge 4 ]; then " +
                                $"{tcpdump} \"not (tcp and host $1 and port $2 and host $3 and port $4)\"; " +
                                $"else {tcpdump} 'not tcp port {port}'; fi";
                var command = client!.CreateCommand(script);
                commands.Add(command);
                var result = command.BeginExecute();
                Interlocked.Increment(ref activeInterfaces);

                var thread = new Thread(() => ReadInterface(name, command, result, onPacket))
                {
                    IsBackground = true,
                    Name = $"Remote capture {name}"
                };
                thread.Start();
            }
        }

        private void ReadInterface(string name, SshCommand command, IAsyncResult result, Action<RawCapture, int> onPacket)
        {
            string reason = "the capture ended";
            try
            {
                PcapStreamReader.ReadAll(command.OutputStream, onPacket, cancel.Token);
                if (!cancel.IsCancellationRequested) reason = ErrorText(command, result) ?? "the router closed the capture";
            }
            catch (Exception ex)
            {
                reason = ErrorText(command, result) ?? ex.Message;
            }
            Interlocked.Decrement(ref activeInterfaces);
            if (!cancel.IsCancellationRequested) InterfaceStopped?.Invoke(name, reason);
        }

        /// <summary>tcpdump's own error message (stderr), without its normal start and end lines.</summary>
        private static string? ErrorText(SshCommand command, IAsyncResult result)
        {
            try
            {
                if (!result.AsyncWaitHandle.WaitOne(2000)) return null;
                command.EndExecute(result);
                var lines = command.Error
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(l => !l.StartsWith("listening on", StringComparison.OrdinalIgnoreCase)
                                && !l.Contains("packets captured") && !l.Contains("packets received by filter")
                                && !l.Contains("packets dropped by kernel"))
                    .ToList();
                return lines.Count > 0 ? string.Join(" ", lines) : null;
            }
            catch
            {
                return null;
            }
        }

        public void Dispose()
        {
            cancel.Cancel();
            if (commands.Count > 0 && client is { IsConnected: true })
            {
                try
                {
                    using var stop = client.CreateCommand(
                        $"for f in /tmp/wecape-{token}-*.pid; do [ -f \"$f\" ] && kill \"$(cat \"$f\")\" 2>/dev/null; rm -f \"$f\"; done");
                    stop.CommandTimeout = TimeSpan.FromSeconds(5);
                    stop.Execute();
                }
                catch
                {
                    // If this fails, tcpdump still exits on its next write once the connection is gone
                }
            }
            foreach (var command in commands)
            {
                try { command.CancelAsync(false, 500); } catch { /* the channel may already be closed */ }
            }
            try { client?.Disconnect(); } catch { /* already gone */ }
            foreach (var command in commands)
            {
                try { command.Dispose(); } catch { /* ignore */ }
            }
            client?.Dispose();
        }
    }
}
