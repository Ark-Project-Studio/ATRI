using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using fNbt;
using Jose;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Protocol;
using Protocol.Minecraft;
using Protocol.Minecraft.Login;
using Protocol.Network.MinecraftPacket;
using Protocol.Utils.Crypto;
using Protocol.Utils.IO;
using SharpRakNet.Network;
using SharpRakNet.Protocol.Raknet;
using SicStream;
using Formatting = System.Xml.Formatting;
using JsonSerializer = System.Text.Json.JsonSerializer;
using Packet = Protocol.Network.Packet;

namespace ATRI.dot_raknet.Network
{
	public class ServerSwitcher
	{
		private RaknetClient? Serversession  = null;
		public delegate void PacketReceive(Packet pk);
		public PacketReceive OnPacketReceive = delegate { };
		public PacketReceive OnCallStartGame = delegate { };
		public delegate void ServerChange();
		public ServerState State { get; set; }
		public ServerChange OnServerChange = delegate { };
		private ulong guid;
		private byte rak_version = 0xB;
		public CompressionAlgorithm CompressionAlgorithm = CompressionAlgorithm.None;
		public bool EnableCompression = false;
		public CryptoContext CryptoContext = new CryptoContext();
		private Lock changeLock = new Lock();
		public SkinDatas skinData = new SkinDatas();

		public void CallPacket(Packet pk)
		{
			
				SendPacket(pk, true);
		}
		public void Switch(IPEndPoint end)
		{
			using (changeLock.EnterScope())
			{
				if (Serversession == null)
				{
				    ChangeServer(end);
					return;
				}

				CompressionAlgorithm = CompressionAlgorithm.None;
				Serversession.EndConnection();
				Serversession = null;
				CryptoContext = new CryptoContext();
				EnableCompression = false;
				ChangeServer(end);
			}
		}
		private void ChangeServer(IPEndPoint endPoint)
		{
			State = ServerState.StartChange;
			Serversession = new RaknetClient();
			Serversession.SessionEstablished += session =>
			{
				session.OnGameSessionReceiveRaw += OnGameSessionReceiveRaw;
			};
			Serversession.BeginConnection(endPoint);
			State = ServerState.Changing;
		}

		private List<Packet> HandlePackage(ref McbeWrapper mcpeWrapper)
		{
			if (CryptoContext.UseEncryption)
			{
				mcpeWrapper.payload = CryptoUtils.Decrypt(mcpeWrapper.payload, CryptoContext);
			}

			

			if (EnableCompression)
			{
				byte compress_id = mcpeWrapper.payload.Span[0];
				return ZLibHelper.Decompress(
					mcpeWrapper.payload[1..],
					(CompressionAlgorithm)compress_id);
			}
			else
			{
				return ZLibHelper.Decompress(
					mcpeWrapper.payload,
					CompressionAlgorithm.None);
			}
		}
		public void SendPacket(List<Packet> packets, bool SendBuf)
		{
				McbeWrapper waWrapper = new();
				waWrapper.payload = SendBuf
					? ZLibHelper.CompressBuff(packets, CompressionAlgorithm, EnableCompression)
					: ZLibHelper.Compress(packets, CompressionAlgorithm, EnableCompression);

				if (CryptoContext.UseEncryption)
				{
					waWrapper.payload = CryptoUtils.Encrypt(waWrapper.payload, CryptoContext);
				}
				lock (Serversession?.Session.Sendq)
	       	Serversession?.Session.Sendq.Insert(Reliability.ReliableOrdered, waWrapper.Encode());
		}
		public void SendPacket(Packet packet, bool SendBuf = false)
		{
			 SendPacket(new List<Packet> { packet }, SendBuf);
		}
		private void OnGameSessionReceiveRaw(IPEndPoint address, byte[] bytes)
		{
			var mcpeWrapper = (McbeWrapper)new McbeWrapper().Decode(bytes);
			var handlePackage = HandlePackage(ref mcpeWrapper);
			foreach (var packet in handlePackage)
			{
				HandlePacket(packet);
			}
		}
		private void HandlePacket(Packet packet)
		{
			switch (packet)
			{
				case McbeNetworkSettings p:
					p.Decode(p.Bytes);
					CompressionAlgorithm = CompressionAlgorithm.ZLib;
					EnableCompression = true;
					HandleNetworkSettings(p);
					break;
				case McbeServerToClientHandshake p:
					p.Decode(p.Bytes);
					HandleServerToClientHandShake(p);
					break;
				default:
					OnPacketReceive(packet);
					break;
			}
		}
		private void HandleNetworkSettings(McbeNetworkSettings pk)
		{
			CompressionAlgorithm = CompressionAlgorithm.ZLib;
			
			CryptoContext.ClientKey = Program.key;
			var jsonObject = new JsonObject();
			jsonObject.Add("AuthenticationType",0);
			jsonObject.Add("Token", Program.Token);
			string singleLineJson = jsonObject.ToJsonString(new JsonSerializerOptions
			{
				WriteIndented = false 
			});
			var bytes = Encoding.UTF8.GetBytes(singleLineJson);
			var mcbeLogin = new McbeLogin();
			var ecDsa = CryptoUtils.ConvertToSingKeyFormat(CryptoContext.ClientKey);
			var encode = JWT.Encode(
				JsonSerializer.Serialize(skinData),
				ecDsa, JwsAlgorithm.ES384, 
				new Dictionary<string, object>
				{
					{ "x5u", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(CryptoContext.ClientKey.Public).GetEncoded().EncodeBase64() }
				});
			var bytes1 = Encoding.UTF8.GetBytes(encode);
			var memoryStream = new MemoryStream();
			var nbtBinaryWriter = new NbtBinaryWriter(memoryStream,false);
			nbtBinaryWriter.Write(bytes.Length);
			nbtBinaryWriter.Write(bytes,0,bytes.Length);
			nbtBinaryWriter.Write(bytes1.Length);
			nbtBinaryWriter.Write(bytes1, 0, bytes1.Length);
			mcbeLogin.payload = memoryStream.ToArray();
			mcbeLogin.protocolVersion = ProtocolInfo.McProtocol;
			memoryStream.DisposeAsync();
			SendPacket(mcbeLogin);
		}
		private void HandleServerToClientHandShake(McbeServerToClientHandshake message)
		{
			string token = message.token;
	

			IDictionary<string, dynamic> headers = JWT.Headers(token);
			string x5u = headers["x5u"];

			var remotePublicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(x5u.DecodeBase64());

			var signParam = new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP384,
				Q =
				{
					X = remotePublicKey.Q.AffineXCoord.GetEncoded(),
					Y = remotePublicKey.Q.AffineYCoord.GetEncoded()
				},
			};
			signParam.Validate();

			var signKey = ECDsa.Create(signParam);
			var data = JWT.Decode<HandshakeData>(token, signKey);
			InitiateEncryption(Base64Url.Decode(x5u),Base64Url.Decode(data.salt));
			State = ServerState.Changed;
		}
		public void InitiateEncryption(byte[] serverKey, byte[] randomKeyToken)
		{
			try
			{
				ECPublicKeyParameters remotePublicKey = (ECPublicKeyParameters)
					PublicKeyFactory.CreateKey(serverKey);

				var agreement = new ECDHBasicAgreement();
				agreement.Init(CryptoContext.ClientKey.Private);
				byte[] secret;
				using (var sha = SHA256.Create())
				{
					secret = sha.ComputeHash(randomKeyToken.Concat(agreement.CalculateAgreement(remotePublicKey).ToByteArrayUnsigned()).ToArray());
				}

				var encryptor = new StreamingSicBlockCipher(new SicBlockCipher(new AesEngine()));
				var decryptor = new StreamingSicBlockCipher(new SicBlockCipher(new AesEngine()));
				decryptor.Init(false, new ParametersWithIV(new KeyParameter(secret), secret.Take(12).Concat(new byte[] { 0, 0, 0, 2 }).ToArray()));
				encryptor.Init(true, new ParametersWithIV(new KeyParameter(secret), secret.Take(12).Concat(new byte[] { 0, 0, 0, 2 }).ToArray()));

				CryptoContext = new CryptoContext
				{
					Decryptor = decryptor,
					Encryptor = encryptor,
					UseEncryption = true,
					Key = secret
				};
				var magic = new McbeClientToServerHandshake();
				SendPacket(magic);
			}
			catch (Exception e)
			{
				Logger.error(string.Format("Initiate encryption", e));
			}
		}
	}
}
