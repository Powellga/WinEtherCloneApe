using System.Net;
using System.Text;

namespace WinEtherCloneApe
{
    /// <summary>A DNS lookup seen on the wire: the name asked for and, in replies, the addresses it resolved to.</summary>
    public sealed record DnsInfo(string QueryName, bool IsResponse, IReadOnlyList<IPAddress> Addresses);

    /// <summary>
    /// Minimal DNS message reader (RFC 1035) for plain DNS on port 53. Reads the question name
    /// and A/AAAA answers; everything else is skipped. Never throws on malformed data.
    /// </summary>
    public static class DnsParser
    {
        public static DnsInfo? TryParse(byte[]? payload)
        {
            if (payload == null || payload.Length < 12) return null;
            try
            {
                bool isResponse = (payload[2] & 0x80) != 0;
                int questions = (payload[4] << 8) | payload[5];
                int answers = (payload[6] << 8) | payload[7];
                if (questions < 1 || questions > 4) return null;

                int pos = 12;
                string? name = ReadName(payload, ref pos);
                if (name == null || pos + 4 > payload.Length) return null;
                pos += 4; // type and class

                for (int q = 1; q < questions; q++)
                {
                    if (ReadName(payload, ref pos) == null || pos + 4 > payload.Length) return null;
                    pos += 4;
                }

                var addresses = new List<IPAddress>();
                for (int a = 0; a < answers && a < 64; a++)
                {
                    if (ReadName(payload, ref pos) == null || pos + 10 > payload.Length) break;
                    int type = (payload[pos] << 8) | payload[pos + 1];
                    int length = (payload[pos + 8] << 8) | payload[pos + 9];
                    pos += 10;
                    if (pos + length > payload.Length) break;
                    if (type == 1 && length == 4) addresses.Add(new IPAddress(payload.AsSpan(pos, 4)));
                    else if (type == 28 && length == 16) addresses.Add(new IPAddress(payload.AsSpan(pos, 16)));
                    pos += length;
                }

                return new DnsInfo(name, isResponse, addresses);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Reads a possibly compressed name and moves pos past it.</summary>
        private static string? ReadName(byte[] data, ref int pos)
        {
            var sb = new StringBuilder();
            int cursor = pos;
            bool jumped = false;
            int jumps = 0;

            while (cursor < data.Length)
            {
                int len = data[cursor];
                if (len == 0)
                {
                    if (!jumped) pos = cursor + 1;
                    return sb.Length == 0 ? "." : sb.ToString();
                }

                if ((len & 0xC0) == 0xC0)
                {
                    if (cursor + 1 >= data.Length || ++jumps > 16) return null;
                    if (!jumped) pos = cursor + 2;
                    jumped = true;
                    cursor = ((len & 0x3F) << 8) | data[cursor + 1];
                    continue;
                }

                if ((len & 0xC0) != 0 || cursor + 1 + len > data.Length) return null;
                if (sb.Length > 0) sb.Append('.');
                for (int i = 0; i < len; i++)
                {
                    char c = (char)data[cursor + 1 + i];
                    sb.Append(c is >= 'A' and <= 'Z' ? (char)(c + 32) : c);
                }
                cursor += 1 + len;
                if (sb.Length > 255) return null;
            }
            return null;
        }
    }
}
