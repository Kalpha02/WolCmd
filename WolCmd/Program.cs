using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Linq.Expressions;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Net.Http.Headers;
using System.Text;

namespace WolCmd
{
    public static class Program
    {
        //static Task<UdpReceiveResult> tasssk;

        public static void Main(string[] Args)
        {
            if (GetArguments(Args, out string MacAddress, out IPAddress? IpAddress, out SubnetMask? Subnetmask, out ushort? Port, out bool? ping, out bool? Debugwol, out byte[]? BytesToAdd))
            {
                //tasssk = new UdpClient(new IPEndPoint(IPAddress.Any, 0)).ReceiveAsync();
                WOL.DebugWOL = Debugwol ?? false;
                Task<bool> Wol = WOL.WakeOnLan(MacAddress, IpAddress, Subnetmask, Port, BytesToAdd);
                Wol.Wait();
                if (!Wol.Result)
                {
                    Console.WriteLine("Something went wrong");
                    return;
                }
                if (!WOL.DebugWOL)
                {
                    Console.WriteLine($"\nMagic Packet succesfully sent to {MacAddress}");
                }
                if (ping ?? false)
                {
                    Console.WriteLine();
                    if (IpAddress == null)
                    {
                        Console.WriteLine("You need to type in an IP-Address to ping the destination");
                        return;
                    }
                    if (IpAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        Subnetmask ??= new SubnetMask(IpAddress);
                        if (IpAddress.Equals(Subnetmask.GetBroadcastAddress(IpAddress)))
                        {
                            Console.WriteLine($"\n{IpAddress} is not pingable");
                            return;
                        }
                    }
                    Console.CancelKeyPress += delegate (object? sender, ConsoleCancelEventArgs e)
                    {
                        Console.WriteLine("\nPing commands cancelled. If you want to ping the target use the Ping.exe");
                    };
                    var p = new Ping();
                    Console.WriteLine($"\nSending pings to {IpAddress}");
                    while (true)
                    {
                        IPStatus PingResult = p.Send(IpAddress).Status;
                        if (PingResult == IPStatus.Success)
                        {
                            Console.WriteLine($"\n{IpAddress} is online");
                            return;
                        }
                        Console.WriteLine(PingResult);
                    }
                }
                /*while (true)
                {
                    System.Threading.Tasks.Task.Delay(10).Wait();

                    if (tasssk.IsCompleted)
                    {
                        Console.WriteLine("\n\n"+string.Concat(tasssk.Result.Buffer.Select(b => b.ToString("X2"))));
                        return;
                    }
                }*/
                return;
            }
            /*if (ExecuteWol(Args))
            {
                Console.CancelKeyPress += delegate (object? sender, ConsoleCancelEventArgs e)
                {
                    Console.WriteLine("\nPing commands cancelled. If you want to ping the target use the Ping.exe");
                };
                return;
            }*/
            Console.WriteLine("\nTo create a Magic Packet to start a device, type in a MAC address\n\n\nYou can also add:\n\n -> IP address\t\tTo target other networks\n -> Subnetmask\n -> Port number\n\nOr some other arguments:\n\n -> -p\t\t\tfor pinging the target\n -> -d\t\t\tfor showing all the Magic Packets\n\nHere a few examples:\n\n -> ABCDEF123456\n -> AB-CD-EF-12-34-56 10.0.0.3 /8 /p\n -> AB:CD:EF:12:34:56 2003:e4:b899:6c47:beef::35 7 /d");


        }

        /// <summary>
        /// Converts arguments from a string. returns false if no MAC address is given or a value is used twice
        /// </summary>
        /// <param name="args"></param>
        /// <param name="MacAddress"></param>
        /// <param name="IpAddress"></param>
        /// <param name="SubnetMask"></param>
        /// <param name="PortNumber"></param>
        /// <param name="Ping"></param>
        /// <returns></returns>
        private static bool GetArguments(string[] args, out string MacAddress, out IPAddress? IpAddress, out SubnetMask? SubnetMask, out ushort? PortNumber, out bool? Ping, out bool? Debug, out byte[]? BytesToAdd)
        {
            string? mac = null;
            IpAddress = null;
            SubnetMask = null;
            PortNumber = null;
            Ping = null;
            Debug = null;
            BytesToAdd = null;

            foreach (string arg in args)
            {
                // Überprüfe, ob das Element eine gültige MAC-Adresse ist
                if (mac == null)
                {
                    if (Verification.CheckMAC(arg))
                    {
                        mac = arg;
                        continue;
                    }
                }
                // Überprüfe, ob das Element eine gültige IP-Adresse ist
                if (IpAddress == null)
                {
                    if (Verification.TryGetIpAddress(arg, out IpAddress))
                    {
                        continue;
                    }
                }
                // Überprüfe, ob das Element eine gültige Subnetzmaske ist
                if (SubnetMask == null)
                {
                    if (Verification.TryGetSubnetMask(arg, out SubnetMask))
                    {
                        continue;
                    }
                }
                // Überprüfe, ob das Element eine gültige Portnummer ist
                if (PortNumber == null)
                {
                    if (Verification.TryGetPortNumber(arg, out PortNumber))
                    {
                        continue;
                    }
                }
                if (Ping == null)
                {
                    if (arg.ToLower().StartsWith("-p"))
                    {
                        Ping = true;
                        continue;
                    }
                }
                if (Debug == null)
                {
                    if (arg.ToLower().StartsWith("-d"))
                    {
                        Debug = true;
                        continue;
                    }
                }
                if (BytesToAdd == null)
                {
                    if (arg.ToLower().StartsWith("-addbytes="))
                    {
                        try
                        {
                            BytesToAdd = Convert.FromHexString(arg.Substring(10));
                            continue;
                        }
                        catch
                        {
                        }
                    }
                }
                MacAddress = string.Empty;
                return false;
            }
            if (string.IsNullOrEmpty(mac))
            {
                MacAddress = string.Empty;
                return false;
            }
            MacAddress = mac;
            return true;
        }
    }

    public static class Verification
    {
        public static bool CheckMAC(string MAC)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(MAC, @"^([0-9A-Fa-f]{2}[: -]?){5}([0-9A-Fa-f]{2})$");
        }

        public static bool TryGetSubnetMask(string InputString, out SubnetMask? Mask)
        {
            try
            {
                Mask = new SubnetMask(InputString);
            }
            catch
            {
                Mask = null;
            }
            return Mask != null;
        }

        public static bool TryGetPortNumber(string InputString, out ushort? PortNumber)
        {
            try
            {
                PortNumber = ushort.Parse(InputString);
            }
            catch
            {
                PortNumber = null;
            }
            return PortNumber != null;
        }

        public static bool TryGetIpAddress(string InputString, out IPAddress? IPAddress)
        {
            if (IPAddress.TryParse(InputString, out IPAddress? address))
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
            IPAddress = null;
            return false;

            bool CheckIPv4(string strIP)
            {
                // Split string by ".", check that array length is 4
                string[] arrOctets = strIP.Split('.');
                if (arrOctets.Length != 4)
                {
                    return false;
                }
                // Check each substring checking that the int value is less than 255 and that is char [] length is !> 2
                Int32 temp; // Parse returns Int32
                foreach (string strOctet in arrOctets)
                {
                    if (strOctet.Length > 3)
                    {
                        return false;
                    }
                    temp = int.Parse(strOctet);
                    if (temp > 255)
                    {
                        return false;
                    }
                }
                return true;
            }
        }
    }
}