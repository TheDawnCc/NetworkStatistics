using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using Newtonsoft.Json;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Statistics;

namespace Example11
{
    /// <summary>
    /// Stat collection capture example
    /// Npcap specific feature
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Stat collection capture example
        /// </summary>

        static Dictionary<string, List<Info>> dic = new Dictionary<string, List<Info>>();
        static Dictionary<DateTime, int> dicCounter = new Dictionary<DateTime, int>();
        static ILiveDevice? device;

        static bool countFlag = true;

        public static void Main()
        {
            Console.CancelKeyPress += Console_CancelKeyPress;


            var ver = Pcap.SharpPcapVersion;
            /* Print SharpPcap version */
            Console.WriteLine("SharpPcap {0}, Example6.DumpTCP.cs", ver);
            Console.WriteLine();

            /* Retrieve the device list */
            var devices = CaptureDeviceList.Instance;

            /*If no device exists, print error */
            if (devices.Count < 1)
            {
                Console.WriteLine("No device found on this machine");
                return;
            }

            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            /* Scan the list printing every entry */
            foreach (var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            device = devices[i];

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            //tcpdump filter to capture only TCP/IP packets
            //string filter = "ip and tcp";
            string filter = "tcp";
            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine
                ("-- The following tcpdump filter will be applied: \"{0}\"",
                filter);
            Console.WriteLine
                ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                device.Description);




            Task.Run(() =>
            {
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();

                while (countFlag)
                {
                    TcpConnectionInformation[] connectionInformation = properties.GetActiveTcpConnections();

                    dicCounter.Add(DateTime.Now, connectionInformation.Length);

                    Thread.Sleep(3000);

                    //foreach (var j in connectionInformation)
                    //{
                    //    Console.WriteLine($"{j.LocalEndPoint} {j.RemoteEndPoint} {j.State}");
                    //}

                }
            });

            // Start capture 'INFINTE' number of packets
            device.Capture();
        }


        private static void Console_CancelKeyPress(object? sender, ConsoleCancelEventArgs e)
        {
            if (Directory.Exists("statistics"))
            {
                Directory.Delete("statistics", true);
            }

            if (File.Exists("data.json"))
            {
                File.Delete("data.json");
            }

            if (File.Exists("count.json"))
            {
                File.Delete("count.json");
            }

            countFlag = false;
            device?.StopCapture();
            Thread.Sleep(3000);

            string str = JsonConvert.SerializeObject(dic);
            string filename = "data.json";
            File.WriteAllText(filename, str);

            str = JsonConvert.SerializeObject(dicCounter);
            filename = "count.json";
            File.WriteAllText(filename, str);

            using (Process p = new Process())
            {
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = "/c python show.py";
                p.Start();
                p.WaitForExit();
            }

            using (Process p = new Process())
            {
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = "/c python showEstablishment.py";
                p.Start();
                p.WaitForExit();
            }

            using (Process p = new Process())
            {
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = "/c python showCount.py";
                p.Start();
                p.WaitForExit();
            }

            Statistics();

            Console.WriteLine("Statistics done!");

            System.Environment.Exit(0);
        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var time = e.Header.Timeval.Date;
            var len = e.Data.Length;
            var rawPacket = e.GetPacket();

            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();

            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                var test = srcIp.ToString();

                // TODO: TCP Count, UDP , different scenario, credential

                var info = new Info
                {
                    time = time,
                    len = len,
                    srcIp = srcIp.ToString(),
                    dstIp = dstIp.ToString(),
                    srcPort = srcPort,
                    dstPort = dstPort,
                };

                string src = $"{srcIp}:{srcPort}";
                string dst = $"{dstIp}:{dstPort}";

                if (tcpPacket.Flags == 2)
                {
                    dic[$"{src}-{dst}"] = new List<Info> { info };

                    Console.WriteLine($"Established Count : {dic.Count}  {time.ToString("HH:mm:ss:ffffff")} Len={len} {srcIp}:{srcPort} -> {dstIp}:{dstPort}");
                }
                else
                {
                    if (dic.ContainsKey($"{src}-{dst}"))
                    {
                        dic[$"{src}-{dst}"].Add(info);
                    }
                    else if (dic.ContainsKey($"{dst}-{src}"))
                    {
                        dic[$"{dst}-{src}"].Add(info);
                    }
                }

            }
        }

        private static void Statistics()
        {
            int maxLen = 0;
            int avgLen = 0;
            double maxEstablishTime = 0;
            double avgEstablishTime = 0;
            int maxEstablishLen = 0;
            int avgEstablishLen = 0;

            var avgLst = new List<Info>();
            var establishLst = new List<List<Info>>();
            var establishTimeLst = new List<TimeSpan>();

            foreach (var i in dic)
            {
                var lst = new List<Info>();
                for (int j = 0; j < i.Value.Count; j++)
                {
                    // establishment
                    if (j < 3)
                    {
                        lst.Add(i.Value[j]);
                    }
                    else
                    {
                        avgLst.Add(i.Value[j]);
                    }
                }
                establishLst.Add(lst);
            }

            foreach (var i in establishLst)
            {
                if (i.Count >= 3)
                {
                    var span = i[2].time - i[0].time;
                    establishTimeLst.Add(span);
                }
            }

            maxLen = avgLst.Max(t => t.len);
            avgLen = (int)avgLst.Average(t => t.len);
            maxEstablishLen = establishLst.Max(t => t.Max(o => o.len));
            avgEstablishLen = (int)establishLst.Average(t => t.Average(o => o.len));
            maxEstablishTime = establishTimeLst.Max(t => t.TotalMilliseconds);
            avgEstablishTime = establishTimeLst.Average(t => t.TotalMilliseconds);

            StringBuilder sb = new StringBuilder();

            sb.Append($"Max Package Len : {maxLen}{Environment.NewLine}");
            sb.Append($"Average Package len : {avgLen}{Environment.NewLine}");
            sb.Append($"Max Establishment Time (ms): {maxEstablishTime} {Environment.NewLine}");
            sb.Append($"Average Establishment Time (ms): {avgEstablishTime} {Environment.NewLine}");
            sb.Append($"Max Establishment Packge Len : {maxEstablishLen} {Environment.NewLine}");
            sb.Append($"Average Establishment Package Len : {avgEstablishLen} {Environment.NewLine}");

            if (!Directory.Exists("Statistics"))
            {
                Directory.CreateDirectory("Statistics");
            }
            string filename = "Statistics\\statistics.txt";
            File.WriteAllText(filename, sb.ToString());
        }

        public static void ShowTcpStatistics()
        {
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpStatistics tcpstat = null;
            Console.WriteLine("");
            tcpstat = properties.GetTcpIPv4Statistics(); ;

            //switch (version)
            //{
            //    case NetworkInterfaceComponent.IPv4:
            //        tcpstat = properties.GetTcpIPv4Statistics();
            //        Console.WriteLine("TCP/IPv4 Statistics:");
            //        break;
            //    case NetworkInterfaceComponent.IPv6:
            //        tcpstat = properties.GetTcpIPv6Statistics();
            //        Console.WriteLine("TCP/IPv6 Statistics:");
            //        break;
            //    default:
            //        throw new ArgumentException("version");
            //        //    break;
            //}

            Console.WriteLine("  Minimum Transmission Timeout............. : {0}",
                tcpstat.MinimumTransmissionTimeout);
            Console.WriteLine("  Maximum Transmission Timeout............. : {0}",
                tcpstat.MaximumTransmissionTimeout);

            Console.WriteLine("  Connection Data:");
            Console.WriteLine("      Current  ............................ : {0}",
            tcpstat.CurrentConnections);
            Console.WriteLine("      Cumulative .......................... : {0}",
                tcpstat.CumulativeConnections);
            Console.WriteLine("      Initiated ........................... : {0}",
                tcpstat.ConnectionsInitiated);
            Console.WriteLine("      Accepted ............................ : {0}",
                tcpstat.ConnectionsAccepted);
            Console.WriteLine("      Failed Attempts ..................... : {0}",
                tcpstat.FailedConnectionAttempts);
            Console.WriteLine("      Reset ............................... : {0}",
                tcpstat.ResetConnections);

            Console.WriteLine("");
            Console.WriteLine("  Segment Data:");
            Console.WriteLine("      Received  ........................... : {0}",
                tcpstat.SegmentsReceived);
            Console.WriteLine("      Sent ................................ : {0}",
                tcpstat.SegmentsSent);
            Console.WriteLine("      Retransmitted ....................... : {0}",
                tcpstat.SegmentsResent);

            Console.WriteLine("");
        }
    }


    class Info
    {
        public int len;
        public DateTime time;
        public int srcPort;
        public int dstPort;
        public string srcIp;
        public string dstIp;
    }
}