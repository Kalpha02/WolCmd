using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Threading.Tasks;

namespace WolCmd
{
    public static class WOL
    {
        public static bool DebugWOL = false;

        public static async Task<bool> WakeOnLan(string macAddress, IPAddress? TargetIp, SubnetMask? Mask, ushort? PortNumber = null, byte[]? BytesToAdd = null)
        {
            if (TargetIp != null)
            {
                if (TargetIp.AddressFamily == AddressFamily.InterNetwork)
                {
                    try
                    {
                        Mask ??= new SubnetMask(TargetIp);
                        TargetIp = Mask.GetBroadcastAddress(TargetIp);
                    }
                    catch
                    {
                        throw;
                    }
                }
            }
            bool Result = false;
            if (!NetworkInterface.GetAllNetworkInterfaces().Where((n) =>
                n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.OperationalStatus == OperationalStatus.Up).Any())
            {
                Console.WriteLine("\nNo Network-Adapters available\n");
                return false;
            }
            byte[] magicPacket = BuildMagicPacket(macAddress).Concat(BytesToAdd ?? new byte[0]).ToArray();
            if (DebugWOL)
            {
                Console.WriteLine(string.Join(" ", magicPacket.Select(b => b.ToString("X2"))));
            }
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces().Where((n) =>
                n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.OperationalStatus == OperationalStatus.Up))
            {
                IPInterfaceProperties iPInterfaceProperties = networkInterface.GetIPProperties();
                foreach (MulticastIPAddressInformation multicastIPAddressInformation in iPInterfaceProperties.MulticastAddresses)
                {
                    IPAddress multicastIpAddress = multicastIPAddressInformation.Address;
                    IPAddress Destination = TargetIp ?? multicastIpAddress;
                    Task<bool> WOLexecution;
                    if (Destination.AddressFamily == AddressFamily.InterNetworkV6 && multicastIpAddress.ToString().StartsWith("ff02::1%", StringComparison.OrdinalIgnoreCase)) // Ipv6: All hosts on LAN (with zone index)
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.FirstOrDefault((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal);
                        if (unicastIPAddressInformation != null)
                        {
                            if (PortNumber is null)
                            {
                                WOLexecution = SendWakeOnLan(unicastIPAddressInformation.Address, Destination, 7, magicPacket);
                                await WOLexecution;
                                Result = WOLexecution.Result || Result;
                                WOLexecution = SendWakeOnLan(unicastIPAddressInformation.Address, Destination, 9, magicPacket);
                                await WOLexecution;
                                Result = WOLexecution.Result || Result;
                            }
                            else
                            {
                                WOLexecution = SendWakeOnLan(unicastIPAddressInformation.Address, Destination, (ushort)PortNumber, magicPacket);
                                await WOLexecution;
                                Result = WOLexecution.Result || Result;
                            }
                        }
                    }
                    else if (multicastIpAddress.ToString().Equals("224.0.0.1")) // Ipv4: All hosts on LAN
                    {
                        UnicastIPAddressInformation? unicastIPAddressInformation = iPInterfaceProperties.UnicastAddresses.FirstOrDefault((u) =>
                            u.Address.AddressFamily == AddressFamily.InterNetwork);
                        if (unicastIPAddressInformation != null)
                        {
                            if (PortNumber is null)
                            {
                                WOLexecution = SendWakeOnLan(unicastIPAddressInformation.Address, Destination, 7, magicPacket);
                                await WOLexecution;
                                Result = WOLexecution.Result || Result;
                                WOLexecution = SendWakeOnLan(unicastIPAddressInformation.Address, Destination, 9, magicPacket);
                                await WOLexecution;
                                Result = WOLexecution.Result || Result;
                            }
                            else
                            {
                                WOLexecution = SendWakeOnLan(unicastIPAddressInformation.Address, Destination, (ushort)PortNumber, magicPacket);
                                await WOLexecution;
                                Result = WOLexecution.Result || Result;
                            }
                        }
                    }
                }
            }
            return Result;
        }

        public static byte[] BuildMagicPacket(string macAddress) // MacAddress in any standard HEX format
        {
            macAddress = System.Text.RegularExpressions.Regex.Replace(macAddress, "[: -]", "");
            byte[] macBytes = Convert.FromHexString(macAddress);

            IEnumerable<byte> header = Enumerable.Repeat((byte)0xff, 6); //First 6 times 0xff
            IEnumerable<byte> data = Enumerable.Repeat(macBytes, 16).SelectMany(m => m); // then 16 times MacAddress
            return header.Concat(data).ToArray();
        }

        private static async Task<bool> SendWakeOnLan(IPAddress localIpAddress, IPAddress multicastIpAddress, ushort PortNumber, byte[] magicPacket)
        {
            bool Debug = DebugWOL;
            if (Debug)
            {
                Console.WriteLine($"\nSending Magic Packet from {localIpAddress} to ");
                for (int i = 6; i < 11; i++)
                {
                    Console.Write(Convert.ToString(magicPacket[i], 16) + "-");
                }
                Console.Write(Convert.ToString(magicPacket[11], 16));
                Console.WriteLine($" via {multicastIpAddress} on Port {PortNumber}...");
            }
            using UdpClient client = new(new IPEndPoint(localIpAddress, 0));
            try
            {
                await client.SendAsync(magicPacket, magicPacket.Length, new IPEndPoint(multicastIpAddress, PortNumber));
            }
            catch (Exception ex)
            {
                if (Debug)
                {
                    if (ex is SocketException)
                    {
                        Console.WriteLine($" -> Destination not reachable from {localIpAddress}");
                    }
                    else
                    {
                        Console.WriteLine(" -> An undefined error occurred");
                    }
                }
                return false;
            }

            if (Debug)
            {
                Console.WriteLine(" -> Magic Packet succesfully sent");
            }
            return true;
        }
    }
}