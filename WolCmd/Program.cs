using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Text.RegularExpressions;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Linq.Expressions;
using System.Threading.Tasks;
using System.Numerics;

namespace WolCmd
{
    public static class Program
    {
        public static void Main(string[] Args)
        {
            if (ExecuteWol(Args))
            {
                return;
            }
            Console.WriteLine("\nTo create a Magic Packet to start a device, use following format:\n\n\n[Mac-Address]\n\n[Mac-Address] [Port number]\n\n[Mac-Address] [IP-Address]\n\n[Mac-Address] [IP-Address] [Port number]\n\n[Mac-Address] [IP-Address] [Subnetmask]\n\n[Mac-Address] [IP-Address] [Subnetmask] [Port number]\n\n\nHere two examples:\n\n -> AB-CD-EF-12-34-56 10.0.0.3 /8\n\n -> AB:CD:EF:12:34:56 192.168.0.104 255.255.255.0 7");
        }

        private static bool ExecuteWol(string[] Args)
        {
            if (Args.Length > 0)
            {
                if (Verification.CheckMAC(Args[0]))
                {
                    Task WakeOnLanCommand;
                    if (Args.Length == 1)
                    {
                        WakeOnLanCommand = WOL.WakeOnLan(Args[0]);
                        WakeOnLanCommand.GetAwaiter().GetResult();
                        if (!WakeOnLanCommand.IsCompletedSuccessfully)
                        {
                            return false;
                        }
                        return true;
                    }
                    IPAddress IP;
                    if (Args.Length == 2)
                    {
                        if (Verification.TryGetIpAddress(Args[1], out IP))
                        {
                            WakeOnLanCommand = WOL.WakeOnLan(Args[0]);
                            WakeOnLanCommand.GetAwaiter().GetResult();
                            if (!WakeOnLanCommand.IsCompletedSuccessfully)
                            {
                                return false;
                            }
                            return true;
                        }
                        if (ushort.TryParse(Args[1], out ushort val))
                        {
                            WakeOnLanCommand = WOL.WakeOnLan(Args[0], val);
                            WakeOnLanCommand.GetAwaiter().GetResult();
                            if (!WakeOnLanCommand.IsCompletedSuccessfully)
                            {
                                return false;
                            }
                            return true;
                        }
                    }
                    if (Args.Length == 3)
                    {
                        if (!Verification.TryGetIpAddress(Args[1], out IP))
                        {
                            return false;
                        }
                        if (ushort.TryParse(Args[2], out ushort val))
                        {
                            WakeOnLanCommand = WOL.WakeOnLan(Args[0], IPAddress.Parse(Args[1]), val);
                            WakeOnLanCommand.GetAwaiter().GetResult();
                            if (!WakeOnLanCommand.IsCompletedSuccessfully)
                            {
                                return false;
                            }
                            return true;
                        }
                        try
                        {
                            SubnetMask mask = new SubnetMask(Args[2]);
                            WakeOnLanCommand = WOL.WakeOnLan(Args[0], IPAddress.Parse(Args[1]), mask);
                            WakeOnLanCommand.GetAwaiter().GetResult();
                            if (!WakeOnLanCommand.IsCompletedSuccessfully)
                            {
                                return false;
                            }
                            return true;
                        }
                        catch (Exception)
                        {
                            return false;
                        }
                    }
                    if (Args.Length == 4)
                    {
                        try
                        {
                            SubnetMask mask = new SubnetMask(Args[2]);
                            WakeOnLanCommand = WOL.WakeOnLan(Args[0], IPAddress.Parse(Args[1]), mask, ushort.Parse(Args[3]));
                            WakeOnLanCommand.GetAwaiter().GetResult();
                            if (!WakeOnLanCommand.IsCompletedSuccessfully)
                            {
                                return false;
                            }
                            return true;
                        }
                        catch { }
                    }
                }
            }
            return false;
        }

        private static bool CheckArgs(string[] Args)
        {
            if (Args.Length == 0 | Args.Contains("?") | Args.Contains("/help"))
            {
                return true;
            }
            if (!Verification.CheckMAC(Args[0]))
            {
                return true;
            }
            return false;
        }
    }

    public static class Verification
    {
        public static bool CheckMAC(string MAC)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(MAC, @"^([0-9A-Fa-f]{2}[: -]?){5}([0-9A-Fa-f]{2})$");
        }

        /// <summary>
        /// </summary>
        /// <param name="ipAddress"></param>
        /// <param name="IPv6Address"></param>
        /// <returns></returns>
        public static bool TryGetIpAddress(string InputString, out IPAddress IPAddress)
        {
            IPAddress address;
            if (IPAddress.TryParse(InputString, out address))
            {
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    IPAddress = address;
                    return true;
                }
                if (CheckIPv4(InputString))
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        IPAddress = address;
                        return true;
                    }
                }
            }
            IPAddress = IPAddress.None;
            return false;

            bool CheckIPv4(string strIP)
            {
                // Split string by ".", check that array length is 4
                char chrFullStop = '.';
                string[] arrOctets = strIP.Split(chrFullStop);
                if (arrOctets.Length != 4)
                {
                    return false;
                }
                // Check each substring checking that the int value is less than 255 and that is char [] length is !> 2
                Int16 MAXVALUE = 255;
                Int32 temp; // Parse returns Int32
                foreach (string strOctet in arrOctets)
                {
                    if (strOctet.Length > 3)
                    {
                        return false;
                    }
                    temp = int.Parse(strOctet);
                    if (temp > MAXVALUE)
                    {
                        return false;
                    }
                }
                return true;
            }
        }
    }

    public static class WOL
    {
        public static async Task WakeOnLan(string macAddress)
        {
            await WakeOnLan(macAddress, 7);
            await WakeOnLan(macAddress, 9);
        }

        public static async Task WakeOnLan(string macAddress, ushort PortNumber)
        {
            byte[] magicPacket = BuildMagicPacket(macAddress);
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces().Where((n) =>
                n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.OperationalStatus == OperationalStatus.Up))
            {
                IPInterfaceProperties iPInterfaceProperties = networkInterface.GetIPProperties();
                foreach (MulticastIPAddressInformation multicastIPAddressInformation in iPInterfaceProperties.MulticastAddresses)
                {
                    IPAddress multicastIpAddress = multicastIPAddressInformation.Address;
                    if (multicastIpAddress.ToString().StartsWith("ff02::1%", StringComparison.OrdinalIgnoreCase)) // Ipv6: All hosts on LAN (with zone index)
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.Where((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal).FirstOrDefault();
                        if (unicastIPAddressInformation != null)
                        {
                            await SendWakeOnLan(unicastIPAddressInformation.Address, multicastIpAddress, PortNumber, magicPacket);
                        }
                    }
                    else if (multicastIpAddress.ToString().Equals("224.0.0.1")) // Ipv4: All hosts on LAN
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.Where((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetwork && !iPInterfaceProperties.GetIPv4Properties().IsAutomaticPrivateAddressingActive).FirstOrDefault();
                        if (unicastIPAddressInformation != null)
                        {
                            await SendWakeOnLan(unicastIPAddressInformation.Address, multicastIpAddress, PortNumber, magicPacket);
                        }
                    }
                }
            }
        }

        public static async Task WakeOnLan(string macAddress, IPAddress TargetIp)
        {
            await WakeOnLan(macAddress, TargetIp, 7);
            await WakeOnLan(macAddress, TargetIp, 9);
        }

        public static async Task WakeOnLan(string macAddress, IPAddress TargetIp, ushort PortNumber)
        {
            try
            {
                TargetIp = new SubnetMask(TargetIp).GetBroadcastAddress(TargetIp);
            }
            catch
            {
                throw;
            }
            byte[] magicPacket = BuildMagicPacket(macAddress);
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces().Where((n) =>
                n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.OperationalStatus == OperationalStatus.Up))
            {
                IPInterfaceProperties iPInterfaceProperties = networkInterface.GetIPProperties();
                foreach (MulticastIPAddressInformation multicastIPAddressInformation in iPInterfaceProperties.MulticastAddresses)
                {
                    IPAddress multicastIpAddress = multicastIPAddressInformation.Address;
                    if (TargetIp.AddressFamily == AddressFamily.InterNetworkV6 && multicastIpAddress.ToString().StartsWith("ff02::1%", StringComparison.OrdinalIgnoreCase)) // Ipv6: All hosts on LAN (with zone index)
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.Where((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal).FirstOrDefault();
                        if (unicastIPAddressInformation != null)
                        {
                            await SendWakeOnLan(unicastIPAddressInformation.Address, TargetIp, PortNumber, magicPacket);
                        }
                    }
                    else if (multicastIpAddress.ToString().Equals("224.0.0.1")) // Ipv4: All hosts on LAN
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.Where((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetwork && !iPInterfaceProperties.GetIPv4Properties().IsAutomaticPrivateAddressingActive).FirstOrDefault();
                        if (unicastIPAddressInformation != null)
                        {
                            await SendWakeOnLan(unicastIPAddressInformation.Address, TargetIp, PortNumber, magicPacket);
                        }
                    }
                }
            }
        }

        public static async Task WakeOnLan(string macAddress, IPAddress TargetIp, SubnetMask Mask)
        {
            await WakeOnLan(macAddress, TargetIp, Mask, 7);
            await WakeOnLan(macAddress, TargetIp, Mask, 9);
        }

        public static async Task WakeOnLan(string macAddress, IPAddress TargetIp, SubnetMask Mask, ushort PortNumber)
        {
            try
            {
                TargetIp = Mask.GetBroadcastAddress(TargetIp);
            }
            catch
            {
                throw;
            }
            byte[] magicPacket = BuildMagicPacket(macAddress);
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces().Where((n) =>
                n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.OperationalStatus == OperationalStatus.Up))
            {
                IPInterfaceProperties iPInterfaceProperties = networkInterface.GetIPProperties();
                foreach (MulticastIPAddressInformation multicastIPAddressInformation in iPInterfaceProperties.MulticastAddresses)
                {
                    IPAddress multicastIpAddress = multicastIPAddressInformation.Address;
                    if (TargetIp.AddressFamily == AddressFamily.InterNetworkV6 && multicastIpAddress.ToString().StartsWith("ff02::1%", StringComparison.OrdinalIgnoreCase)) // Ipv6: All hosts on LAN (with zone index)
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.Where((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal).FirstOrDefault();
                        if (unicastIPAddressInformation != null)
                        {
                            await SendWakeOnLan(unicastIPAddressInformation.Address, TargetIp, PortNumber, magicPacket);
                        }
                    }
                    else if (multicastIpAddress.ToString().Equals("224.0.0.1")) // Ipv4: All hosts on LAN
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.Where((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetwork && !iPInterfaceProperties.GetIPv4Properties().IsAutomaticPrivateAddressingActive).FirstOrDefault();
                        if (unicastIPAddressInformation != null)
                        {
                            await SendWakeOnLan(unicastIPAddressInformation.Address, TargetIp, PortNumber, magicPacket);
                        }
                    }
                }
            }
        }

        public static byte[] BuildMagicPacket(string macAddress) // MacAddress in any standard HEX format
        {
            macAddress = Regex.Replace(macAddress, "[: -]", "");
            byte[] macBytes = Convert.FromHexString(macAddress);

            IEnumerable<byte> header = Enumerable.Repeat((byte)0xff, 6); //First 6 times 0xff
            IEnumerable<byte> data = Enumerable.Repeat(macBytes, 16).SelectMany(m => m); // then 16 times MacAddress
            return header.Concat(data).ToArray();
        }

        private static async Task<bool> SendWakeOnLan(IPAddress localIpAddress, IPAddress multicastIpAddress, ushort PortNumber, byte[] magicPacket)
        {
            Console.WriteLine($"\nSending Magic Packet from {localIpAddress} to ");
            for (int i = 6; i < 11; i++)
            {
                Console.Write(Convert.ToString(magicPacket[i], 16) + "-");
            }
            Console.Write(Convert.ToString(magicPacket[11], 16));
            Console.WriteLine($" via {multicastIpAddress} on Port {PortNumber}...");
            using UdpClient client = new(new IPEndPoint(localIpAddress, 0));
            try
            {
                await client.SendAsync(magicPacket, magicPacket.Length, new IPEndPoint(multicastIpAddress, PortNumber));
            }
            catch (Exception ex)
            {
                if (ex is SocketException SoEx)
                {
                    Console.WriteLine($" -> Destination not reachable from {localIpAddress}");
                    return false;
                }
                Console.WriteLine(" -> An undefined error occurred");
                return false;
            }
            Console.WriteLine(" -> Magic Packet succesfully sent");
            return true;
        }
    }

    public class SubnetMask
    {
        private readonly byte[] _bytes;

        public SubnetMask(IPAddress iPAddress)
        {
            if (iPAddress == null)
            {
                throw new ArgumentNullException(nameof(iPAddress));
            }

            byte FirstOctet = 0;
            FirstOctet = byte.Parse(iPAddress.ToString().Split('.')[0]);
            _bytes = new byte[] { 0, 0, 0, 0 };
            _bytes[0] = 255;
            if (FirstOctet > 127)
            {
                _bytes[1] = 255;
            }
            if (FirstOctet > 191)
            {
                _bytes[2] = 255;
            }
            if (FirstOctet > 223)
            {
                throw new Exception("Something unknown happened");
            }
        }

        public SubnetMask(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            if (bytes.Length != 4)
            {
                throw new ArgumentException("Subnet mask must contain exactly 4 bytes.", nameof(bytes));
            }

            _bytes = bytes;
        }

        public SubnetMask(string subnetMask)
        {
            if (string.IsNullOrEmpty(subnetMask))
            {
                throw new ArgumentNullException(nameof(subnetMask));
            }

            _bytes = new byte[4];

            if (subnetMask.Split('.').Length == 4)
            {
                for (byte i = 0; i < 4; i++)
                {
                    if (!byte.TryParse(subnetMask.Split('.')[i], out _bytes[i]))
                    {
                        throw new ArgumentException("Invalid subnet mask format.", nameof(subnetMask));
                    }
                }
                if (!IsValidSubnetMask(_bytes[0], _bytes[1], _bytes[2], _bytes[3]))
                {
                    throw new ArgumentException("Invalid subnet mask format.", nameof(subnetMask));
                }
                return;
            }

            byte subnetMaskLength;
            if (byte.TryParse(subnetMask.TrimStart('/'), out subnetMaskLength))
            {
                if (subnetMaskLength < 2 | subnetMaskLength > 31)
                {
                    throw new ArgumentOutOfRangeException(nameof(subnetMaskLength), "Subnetmask length need to be between 2 and 30");
                }
                for (int i = 0; i < subnetMaskLength; i++)
                {
                    _bytes[i / 8] |= (byte)(1 << (7 - i % 8));
                }
                return;
            }
            throw new ArgumentException("Invalid subnet mask format.", nameof(subnetMask));
        }

        public IPAddress GetBroadcastAddress(IPAddress ipAddress)
        {
            if (ipAddress == null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }
            if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                throw new Exception("IP Address must be version 4");
            }

            byte[] ipAddressBytes = ipAddress.GetAddressBytes();
            byte[] subnetMaskBytes = this.GetBytes();

            byte[] broadcastAddressBytes = new byte[ipAddressBytes.Length];
            for (int i = 0; i < broadcastAddressBytes.Length; i++)
            {
                broadcastAddressBytes[i] = (byte)(ipAddressBytes[i] | (subnetMaskBytes[i] ^ 255));
            }

            return new IPAddress(broadcastAddressBytes);
        }

        public bool IsValidSubnetMask(byte octet1, byte octet2, byte octet3, byte octet4)
        {
            BitList bits = BitList.ToBitList(octet1, 8);
            bits.AddRange(BitList.ToBitList(octet2, 8));
            bits.AddRange(BitList.ToBitList(octet3, 8));
            bits.AddRange(BitList.ToBitList(octet4, 8));
            bits = bits.TrimStart(1);
            if (bits.Count <= 1 || bits.Count > 31)
            {
                return false;
            }
            if ((BigInteger)bits == 0)
            {
                return true;
            }
            return false;
        }

        public byte[] GetBytes()
        {
            return _bytes;
        }

        public override string ToString()
        {
            return $"{_bytes[0]}.{_bytes[1]}.{_bytes[2]}.{_bytes[3]}";
        }
    }
}