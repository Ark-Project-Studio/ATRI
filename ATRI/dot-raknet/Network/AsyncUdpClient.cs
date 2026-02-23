using SharpRakNet.Protocol.Raknet;

using System.Net.Sockets;
using System.Net;
using System;

namespace SharpRakNet.Network
{
    public class AsyncUdpClient
    {
        public UdpClient Socket;

        public delegate void PacketReceivedDelegate(IPEndPoint address, byte[] packet);
        public PacketReceivedDelegate PacketReceived = delegate { };
        private AsyncCallback recv = null;
        private bool _closed = false;


        public AsyncUdpClient()
        {
            Socket = Common.CreateListener(new IPEndPoint(IPAddress.Any, 0));
        }

        public AsyncUdpClient(IPEndPoint address)
        {
            Socket = Common.CreateListener(address);
        }

        public void Send(IPEndPoint address, byte[] packet)
        {
            try
            {
                   Socket.SendAsync(packet,address);    
                
            } catch {};
        }

        public void Run()
        {
            IPEndPoint source = new IPEndPoint(0, 0);
            Thread thread = new Thread((() =>
            {
	            while (true)
	            {
		            if (_closed)
		            {
						Socket?.Close();
                        return;
					}
					var receive = Socket.Receive(ref source);
		            PacketReceived(source, receive);
		          
	            }
			}));
            thread.Start();
        }

        public void Stop()
        {
            _closed = true;
        }
    }

}
