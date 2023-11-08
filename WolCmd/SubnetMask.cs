using System.Net.Sockets;
using System.Net;
using System.Numerics;

namespace WolCmd
{
    public class SubnetMask
    {
        private readonly byte Prefix = 0;

        public SubnetMask(IPAddress iPAddress)
        {
            if (iPAddress == null)
            {
                throw new ArgumentNullException(nameof(iPAddress));
            }
            if (iPAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Prefix = 64;
                return;
            }

            byte FirstOctet = byte.Parse(iPAddress.ToString().Split('.')[0]);

            Prefix = FirstOctet switch
            {
                < 128 => 8,
                < 192 => 16,
                < 224 => 24,
                _ => throw new Exception("Class D and higher isn't supported")
            };
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

            BitList bits = bytes;
            if (bits.TrimStart(true) != 0)
            {
                throw new ArgumentException("Subnet mask need to start with ones and end with 0. In between where mustn't be a change from 0 to 1", nameof(bytes));
            }
            foreach (Bit b in bits)
            {
                if (b == false)
                {
                    break;
                }
                ++Prefix;
            }
        }

        public SubnetMask(string subnetMask)
        {
            if (string.IsNullOrEmpty(subnetMask))
            {
                throw new ArgumentNullException(nameof(subnetMask));
            }

            if (byte.TryParse(subnetMask.TrimStart('/'), out byte subnetMaskLength))
            {
                try
                {
                    if (subnetMaskLength < 3 | subnetMaskLength > 126)
                    {
                        throw new ArgumentOutOfRangeException(nameof(subnetMaskLength), "Subnetmask length need to be between 3 and 126");
                    }
                    Prefix = subnetMaskLength;
                }
                catch
                {
                    throw;
                }
                return;
            }

            if (subnetMask.Split('.').Length == 4)
            {
                try
                {
                    //ERGÄNZEN
                }
                catch (Exception)
                {
                    throw;
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

        public static bool IsValidSubnetMask(byte octet1, byte octet2, byte octet3, byte octet4)
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

        public bool IsIPv4Mask()
        {
            if (Prefix < 31)
            {
                return true;
            }
            return false;
        }

        public byte[] GetBytes()
        {
            if (Prefix > 30)
            {
                throw new Exception("This funtion does only work with IPv4");
            }
            BitList result = new BitList();
            byte n = Prefix;
            while (n-- != 0)
            {
                result.Add(true);
            }
            return result.PadRight(32, false).ToByteArray();
        }

        public override string ToString() => ToString(false);

        public virtual string ToString(Bit PreferPrefix)
        {
            if (!PreferPrefix)
            {
                if (IsIPv4Mask())
                {
                    byte[] bytes = GetBytes();
                    return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
                }
            }
            return $"/{Prefix}";
        }
    }
}