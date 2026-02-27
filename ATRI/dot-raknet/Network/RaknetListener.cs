using SharpRakNet.Protocol.Raknet;

using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.Net;
using System;
using ATRI.dot_raknet.Network;
using ATRI.Global;
using Protocol.Network.MinecraftPacket;
using OpenConnectionReply1 = SharpRakNet.Protocol.Raknet.OpenConnectionReply1;
using OpenConnectionReply2 = SharpRakNet.Protocol.Raknet.OpenConnectionReply2;
using OpenConnectionRequest2 = SharpRakNet.Protocol.Raknet.OpenConnectionRequest2;

namespace SharpRakNet.Network
{
    public class RaknetListener
    {
        public delegate void SessionConnectedDelegate(RaknetSession session);
        public SessionConnectedDelegate SessionConnected = delegate { };
        public AsyncUdpClient Socket;

        private static readonly Dictionary<int, List<(Type, Delegate)>> Listeners = new Dictionary<int, List<(Type, Delegate)>>();
        private Dictionary<IPEndPoint, MinecraftClient> Sessions = new Dictionary<IPEndPoint,MinecraftClient>();

        private byte rak_version = 0xB;
        private long guid;

        public RaknetListener(IPEndPoint address)
        {
            Socket = new AsyncUdpClient(address);
            Socket.PacketReceived += OnPacketReceived;
            SessionConnected += OnSessionEstablished;
            guid = 114514;
        }

        private void OnSessionEstablished(RaknetSession session)
        {
            session.SessionReceiveRaw += OnPacketReceived;
            session.SessionDisconnected += RemoveSession;
        }

        void RemoveSession(RaknetSession session)
        {
            session.SessionReceiveRaw -= OnPacketReceived;
            IPEndPoint peerAddr = session.PeerEndPoint;

            lock(Sessions)
                Sessions.Remove(peerAddr);
        }

        private void OnPacketReceived(IPEndPoint address, byte[] data)
        {
            switch ((PacketID)data[0]) {
                case PacketID.OpenConnectionRequest1:
                    HandleOpenConnectionRequest1(address, data);
                    break;
                case PacketID.OpenConnectionRequest2:
                    HandleOpenConnectionRequest2(address, data);
                    break;
				case PacketID.UnconnectedPing1:
                case PacketID.UnconnectedPing2:
                    HandleUnconnectping(address,data);
                    break;
                default:
                    {
                        if (Sessions.TryGetValue(address, out var session))
                        {
                            session.Session.HandleFrameSet(address, data);
                        }
                        break;
                    }
            }
        }
        private void  HandleUnconnectping(IPEndPoint address, byte[] bytes)
        {
	        var unconnectedPing = new UnconnectedPing();
	        unconnectedPing.Decode(bytes);

	        var unconnectedPong = new UnconnectedPong();
            unconnectedPong.pingId = unconnectedPing.pingId;
            unconnectedPong.serverId = guid;
            unconnectedPong.serverName = "MCPE;Dedicated Server;390;1.14.60;0;10;13253860892328930865;Bedrock level;Survival;1;19132;19133;";
            Socket.Send(address, unconnectedPong.Encode());
		}

        private void HandleOpenConnectionRequest1(IPEndPoint peer_addr, byte[] data)
        {
            OpenConnectionReply1 reply1Packet = new OpenConnectionReply1
            {
                magic = true,
                guid = (ulong)guid,
                use_encryption = 0x00,
                mtu_size = Common.RAKNET_CLIENT_MTU,
            };
            byte[] reply1Buf = Packet.WritePacketConnectionOpenReply1(reply1Packet);
            Socket.Send(peer_addr, reply1Buf);
        }

        private void HandleOpenConnectionRequest2(IPEndPoint peer_addr, byte[] data)
        {
            OpenConnectionRequest2 req = Packet.ReadPacketConnectionOpenRequest2(data);
            OpenConnectionReply2 reply2Packet = new OpenConnectionReply2
            {
                magic = true,
                guid = (ulong)guid,
                address = peer_addr,
                mtu = req.mtu,
                encryption_enabled = 0x00,
            };
            byte[] reply2Buf = Packet.WritePacketConnectionOpenReply2(reply2Packet);
            var session = new RaknetSession(Socket, peer_addr, (ulong)guid, rak_version, new RecvQ(), new SendQ(req.mtu));
            lock (Sessions)
            {
	            var client = new MinecraftClient(session);
	            var add = Sessions.TryAdd(peer_addr, client);
	            if (add)
	            {
		            
					GlobalEvent.OnClientRaknetConnected?.Invoke(client);
					Socket.Send(peer_addr, reply2Buf);
					SessionConnected(session);
				}
            }
        }

        public void BeginListener()
        {
            Socket.Run();
        }

        public void StopListener()
        {
            lock (Sessions)
            {
                for (int i = Sessions.Count - 1; i >= 0; i--)
                {
                    var session = Sessions.Values.ElementAt(i);
                    session.Session.SessionDisconnected(session.Session);
                }
            }
            Socket.Stop();
        }

    }
}
