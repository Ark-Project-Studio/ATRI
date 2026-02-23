using System;
using System.Collections.Generic;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Channels;
using Protocol;
using Protocol.Minecraft;
using Protocol.Network.MinecraftPacket;
using Protocol.Utils;
using Protocol.Utils.Crypto;
using Protocol.Utils.IO;
using SharpRakNet.Protocol.Raknet;
using ConnectedPing = SharpRakNet.Protocol.Raknet.ConnectedPing;
using ConnectedPong = SharpRakNet.Protocol.Raknet.ConnectedPong;
using ConnectionRequest = SharpRakNet.Protocol.Raknet.ConnectionRequest;
using ConnectionRequestAccepted = SharpRakNet.Protocol.Raknet.ConnectionRequestAccepted;
using NewIncomingConnection = SharpRakNet.Protocol.Raknet.NewIncomingConnection;

namespace SharpRakNet.Network
{
    public class RaknetSession
    {
        public IPEndPoint PeerEndPoint { get; private set; }
        
        public Thread SenderThread;
        public byte rak_version;
        public Timer PingTimer;
        public bool Connected;
        public Thread HandleThread;
		public RecvQ Recvq;
        public SendQ Sendq;
        private readonly AsyncUdpClient Socket;
        public int MaxRepingCount = 6;
        private int repingCount;
        private ulong guid;
        private Channel<Action> taskChannel = Channel.CreateUnbounded<Action>();
		public delegate void SessionDisconnectedDelegate(RaknetSession session);
        public SessionDisconnectedDelegate SessionDisconnected = delegate { };

        public delegate void PacketReceive(IPEndPoint address, byte[] bytes);
        public PacketReceive SessionReceiveRaw = delegate { };
        public delegate void GamePacketReceive(IPEndPoint address, byte[] bytes);
        public GamePacketReceive OnGameSessionReceiveRaw = delegate { };
        

		public RaknetSession(AsyncUdpClient Socket, IPEndPoint Address, ulong guid, byte rakVersion, RecvQ recvQ, SendQ sendQ)
        {
			HandleThread = new Thread((Start));
			HandleThread.Start();
			this.Socket = Socket;
            PeerEndPoint = Address;
            this.guid = guid;
            Connected = true;

            rak_version = rakVersion;

            Sendq = sendQ;
            Recvq = recvQ;

            StartPing();
            SenderThread = StartSender();
        }
        private async void Start()
        {
	        var reader = taskChannel.Reader;
	        await foreach (var action in reader.ReadAllAsync())
	        {
				try
				{
					action?.Invoke();
				}
				catch (Exception e)
				{
					Logger.error(e);
				}
			}
        }
		public void HandleFrameSet(IPEndPoint peer_addr, byte[] data)
		{
			if (!Connected)
			{
				foreach (FrameSetPacket f in Recvq.Flush(peer_addr))
				{
					HandleFrame(peer_addr, f);
				}
			}

			if (Abort)
			{
				return;
			}
			taskChannel.Writer.TryWrite((() =>
			{

				RaknetReader stream = new RaknetReader(data);
				byte headerFlags = stream.ReadU8();

				switch ((PacketID)headerFlags)
				{
					case PacketID.Nack:
					{
						lock (Sendq)
						{
							Nack nack = Packet.ReadPacketNack(data);
							for (int i = 0; i < nack.record_count; i++)
							{
								if (nack.sequences[i].Start == nack.sequences[i].End)
								{
									Sendq.Nack(nack.sequences[i].Start, Common.CurTimestampMillis());
								}
								else
								{
									for (uint j = nack.sequences[i].Start; j <= nack.sequences[i].End; j++)
									{
										Sendq.Nack(j, Common.CurTimestampMillis());
									}
								}
							}
						}

						break;
					}
					case PacketID.Ack:
					{
						lock (Sendq)
						{
							Ack ack = Packet.ReadPacketAck(data);
							for (int i = 0; i < ack.record_count; i++)
							{
								if (ack.sequences[i].Start == ack.sequences[i].End)
								{
									Sendq.Ack(ack.sequences[i].Start, Common.CurTimestampMillis());
								}
								else
								{
									for (uint j = ack.sequences[i].Start; j <= ack.sequences[i].End; j++)
									{
										Sendq.Ack(j, Common.CurTimestampMillis());
									}
								}
							}
						}

						break;
					}
					default:
					{
						if ((PacketID)data[0] >= PacketID.FrameSetPacketBegin
						    && (PacketID)data[0] <= PacketID.FrameSetPacketEnd)
						{
							var frames = new FrameVec(data);
							lock (Recvq)
							{
								foreach (var frame in frames.frames)
								{
									Recvq.Insert(frame);
									foreach (FrameSetPacket f in Recvq.Flush(peer_addr))
									{
										HandleFrame(peer_addr, f);
									}
								}

							}
							var acks = Recvq.GetAck();
							if (acks.Count != 0)
							{
								Ack packet = new Ack
								{
									record_count = (ushort)acks.Count,
									sequences = acks,
								};
								byte[] buf = Packet.WritePacketAck(packet);
								Socket.Send(peer_addr, buf);
							}
						}
						break;
					}
				}

			}));
			
		}

		public void HandleFrame(IPEndPoint address, FrameSetPacket frame)
        {
            PacketID packetID = (PacketID)frame.data[0];

            switch (packetID)
            {
                case PacketID.ConnectedPing:
                    HandleConnectPing(frame.data);
                    break;
                case PacketID.ConnectedPong:
                    repingCount = 0;
                    break;
                case PacketID.ConnectionRequest:
                    HandleConnectionRequest(address, frame.data);
                    break;
                case PacketID.ConnectionRequestAccepted:
                    HandleConnectionRequestAccepted(frame.data);
                    var mcpeRequestNetworkSettings = new McbeRequestNetworkSettings();
                    mcpeRequestNetworkSettings.protocolVersion = ProtocolInfo.McProtocol;
                    var memoryStream = new MemoryStream();
                    var encode = mcpeRequestNetworkSettings.Encode();
                    VarInt.WriteUInt32(memoryStream,(uint)encode.Length);
                    memoryStream.Write(encode);
					var mcpeWrapper = new McbeWrapper();
                    mcpeWrapper.payload = memoryStream.ToArray();
                    lock(Sendq)
                     Sendq.Insert(Reliability.ReliableOrdered,mcpeWrapper.Encode());
                    break;
                case PacketID.NewIncomingConnection:
                    break;
                case PacketID.Disconnect:
                    HandleDisconnectionNotification();
                    break;
				case PacketID.Game:
                     OnGameSessionReceiveRaw(address,frame.data);
                    break;
                default:
                    SessionReceiveRaw(address, frame.data);
                    break;
            }
        }
        private void HandleConnectPing(byte[] data)
        {
            ConnectedPing pingPacket = Packet.ReadPacketConnectedPing(data);
            ConnectedPong pongPacket = new ConnectedPong
            {
                client_timestamp = pingPacket.client_timestamp,
                server_timestamp = Common.CurTimestampMillis(),
            };

            byte[] buf = Packet.WritePacketConnectedPong(pongPacket);
            lock (Sendq)
				Sendq.Insert(Reliability.ReliableOrdered, buf);
        }

        private void HandleConnectionRequestAccepted(byte[] data)
        {
            ConnectionRequestAccepted packet = Packet.ReadPacketConnectionRequestAccepted(data);
            NewIncomingConnection packet_reply = new NewIncomingConnection
            {
                server_address = (IPEndPoint)Socket.Socket.Client.LocalEndPoint,
                request_timestamp = packet.request_timestamp,
                accepted_timestamp = Common.CurTimestampMillis(),
            };
            byte[] buf = Packet.WritePacketNewIncomingConnection(packet_reply);
            lock (Sendq)
				Sendq.Insert(Reliability.ReliableOrdered, buf);
        }

        private void HandleConnectionRequest(IPEndPoint peer_addr, byte[] data)
        {
            ConnectionRequest packet = Packet.ReadPacketConnectionRequest(data);
            ConnectionRequestAccepted packet_reply = new ConnectionRequestAccepted
            {
                client_address = peer_addr,
                system_index = 0,
                request_timestamp = packet.time,
                accepted_timestamp = Common.CurTimestampMillis(),
            };
            byte[] buf = Packet.WritePacketConnectionRequestAccepted(packet_reply);
            lock (Sendq)
				Sendq.Insert(Reliability.ReliableOrdered, buf);
        }

        private bool Abort = false;
        private void HandleDisconnectionNotification()
        {
           StopSession();
        }
        public void StopSession()
        {
			Connected = false;
			Abort = true;
			PingTimer.Dispose();
			SessionDisconnected(this);
			GC.Collect();
		}

        public void HandleConnect()
        {
            ConnectionRequest requestPacket = new ConnectionRequest
            {
                guid = guid,
                time = Common.CurTimestampMillis(),
                use_encryption = 0x00,
            };
            byte[] buf = Packet.WritePacketConnectionRequest(requestPacket);
			lock (Sendq)
				Sendq.Insert(Reliability.ReliableOrdered, buf);
        }

        public Thread StartSender()
        {
            Thread thread = new Thread(() => 
            {
                while (!Abort)
                {
                    Thread.Sleep(20);
                    lock (Sendq)
						foreach (FrameSetPacket item in Sendq.Flush(Common.CurTimestampMillis(), PeerEndPoint))
                    {
                        byte[] sdata = item.Serialize();
                        Socket.Send(PeerEndPoint, sdata);
                    }
                }
            });
            thread.Start();
            return thread;
        }

        public void StartPing()
        {
            PingTimer = new Timer(SendPing, null,
                new Random().Next(1000, 1500), new Random().Next(1000, 1500));
        }

        public void SendPing(object obj)
        {
            if (!Connected) return;
            ConnectedPing pingPacket = new ConnectedPing
            {
                client_timestamp = Common.CurTimestampMillis(),
            };

            byte[] buffer = Packet.WritePacketConnectedPing(pingPacket);
			lock (Sendq)
				Sendq.Insert(Reliability.Unreliable, buffer);

            repingCount++;
            if (repingCount < MaxRepingCount) return;

            HandleDisconnectionNotification();
        }
    }
}
