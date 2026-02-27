using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using ATRI.Global;
using fNbt;
using Jose;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Protocol;
using Protocol.Minecraft;
using Protocol.Minecraft.Login;
using Protocol.Network;
using Protocol.Network.MinecraftPacket;
using Protocol.Utils;
using Protocol.Utils.Crypto;
using Protocol.Utils.IO;
using SharpRakNet.Network;
using SharpRakNet.Protocol.Raknet;
using SicStream;
using Packet = Protocol.Network.Packet;

namespace ATRI.dot_raknet.Network
{
	public class MinecraftClient
	{
	
		public RaknetSession Session;
		public CompressionAlgorithm CompressionAlgorithm = CompressionAlgorithm.None;
		public bool EnableCompression = false;
		public CryptoContext CryptoContext = new CryptoContext();
		public ServerSwitcher ServerSwitcher = new ServerSwitcher();
		public MinecraftClient(RaknetSession session)
		{
			
			Session = session;
			Session.OnGameSessionReceiveRaw += SessionReceiveRaw;
			ServerSwitcher.OnPacketReceive += OnPacketReceive;
			ServerSwitcher.OnCallPacket += pk =>
			{
				SendPacket(pk);
			};
			GlobalEvent.OnClientRaknetConnected?.Invoke(this);
		}

		private void OnPacketReceive(Packet pk)
		{
			if (pk is McbeDisconnect)
			{
				GlobalEvent.OnClientMCDisConnected?.Invoke(this);
			}
			var receive = GlobalEvent.OnServerPacketReceive?.Invoke(ServerSwitcher, pk);
			if (receive is UnknownPacket)
			{
				return;
			}
			SendPacket(pk, true);
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
				lock (Session.Sendq)
			    Session.Sendq.Insert(Reliability.ReliableOrdered, waWrapper.Encode());
		}
		public void SendPacket(Packet packet,bool SendBuf = false)
		{
			 SendPacket(new List<Packet> { packet },SendBuf);
		}
		
		private void SessionReceiveRaw(IPEndPoint address, byte[] bytes)
		{
			var mcpeWrapper = (McbeWrapper)new McbeWrapper().Decode(bytes);
			var handlePackage = HandlePackage(ref mcpeWrapper);
			foreach (var packet in handlePackage)
			{
				HandlePacket(packet);
			}
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
		private void HandlePacket(Packet packet)
		{
		//Logger.info(packet);
			switch (packet)
			{
				case McbeRequestNetworkSettings s:
					s.Decode(s.Bytes);
					HandleRequestNetworkSettings(s);
					break;
				case McbeLogin p:
					p.Decode(p.Bytes);
					HandleLoginPacket(p);
					break;
				case McbeClientToServerHandshake p:
					break;
			    case McbeText p:
					var disconnect = new McbeDisconnect();
					disconnect.message = "114514";
					disconnect.hideDisconnectReason = false;
					disconnect.failReason = McbeDisconnect.DisconnectReason.BannedSkin;
					SendPacket(disconnect);
					break;
				case McbeDisconnect p:
					GlobalEvent.OnClientMCDisConnected?.Invoke(this);
					break;
				default:
					var receive = GlobalEvent.OnClientPacketReceive?.Invoke(this, packet);
					if (receive is UnknownPacket)
					{
						break;
					}
					ServerSwitcher.CallPacket(packet);
					break;
			}
		}
		private void HandleLoginPacket(McbeLogin message)
		{
			byte[] buffer = message.payload;
			string certificateChain;
			string skinData;
			var destination = new MemoryStream(buffer);
			destination.Position = 0;
			NbtBinaryReader reader = new NbtBinaryReader(destination, false);

			var countCertData = reader.ReadInt32();
			certificateChain = Encoding.UTF8.GetString(reader.ReadBytes(countCertData));
			Logger.info(certificateChain);
			var countSkinData = reader.ReadInt32();
			skinData = Encoding.UTF8.GetString(reader.ReadBytes(countSkinData));
			var deserialize = JsonSerializer.Deserialize<SkinDatas>(JWT.Payload(skinData));
			ServerSwitcher.skinData = deserialize;
			ServerSwitcher.Switch(IPEndPoint.Parse("127.0.0.1:19132"));
			Logger.info($"{deserialize.ThirdPartyName} Joined the game");
			var payload = JWT.Payload(JsonObject.Parse(certificateChain)["Token"].ToString());
			GetSalt(JsonObject.Parse(payload)["cpk"].ToString());
		}
		private void HandleRequestNetworkSettings(McbeRequestNetworkSettings packet)
		{
			var network = new McbeNetworkSettings();
			network.compressionAlgorithm = 0x00;
			network.compressionThreshold = 1000;
			network.clientThrottleEnabled = false; network.clientThrottleScalar = 0;
			network.clientThrottleThreshold = 0;
			SendPacket(network);
			CompressionAlgorithm = CompressionAlgorithm.ZLib;
			EnableCompression = true;

		}
		private void GetSalt(string IdentityPublicKey)
		{
			// Use bouncy to parse the DER key
			ECPublicKeyParameters remotePublicKey = (ECPublicKeyParameters)
				PublicKeyFactory.CreateKey(IdentityPublicKey.DecodeBase64());

			var b64RemotePublicKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(remotePublicKey).GetEncoded().EncodeBase64();
			var generator = new ECKeyPairGenerator("ECDH");
			generator.Init(new ECKeyGenerationParameters(remotePublicKey.PublicKeyParamSet, SecureRandom.GetInstance("SHA256PRNG")));
			var keyPair = generator.GenerateKeyPair();

			ECPublicKeyParameters pubAsyKey = (ECPublicKeyParameters)keyPair.Public;
			ECPrivateKeyParameters privAsyKey = (ECPrivateKeyParameters)keyPair.Private;

			var secretPrepend = Encoding.UTF8.GetBytes("RANDOM SECRET");

			ECDHBasicAgreement agreement = new ECDHBasicAgreement();
			agreement.Init(keyPair.Private);
			byte[] secret;
			using (var sha = SHA256.Create())
			{
				secret = sha.ComputeHash(secretPrepend.Concat(agreement.CalculateAgreement(remotePublicKey).ToByteArrayUnsigned()).ToArray());
			}

			Debug.Assert(secret.Length == 32);

		
			var encryptor = new StreamingSicBlockCipher(new SicBlockCipher(new AesEngine()));
			var decryptor = new StreamingSicBlockCipher(new SicBlockCipher(new AesEngine()));
			decryptor.Init(false, new ParametersWithIV(new KeyParameter(secret), secret.Take(12).Concat(new byte[] { 0, 0, 0, 2 }).ToArray()));
			encryptor.Init(true, new ParametersWithIV(new KeyParameter(secret), secret.Take(12).Concat(new byte[] { 0, 0, 0, 2 }).ToArray()));
			CryptoContext.Key = secret;
			CryptoContext.Decryptor = decryptor;
			CryptoContext.Encryptor = encryptor;

			var signParam = new ECParameters
			{
				Curve = ECCurve.NamedCurves.nistP384,
				Q =
								{
									X = pubAsyKey.Q.AffineXCoord.GetEncoded(),
									Y = pubAsyKey.Q.AffineYCoord.GetEncoded()
								}
			};
			signParam.D = CryptoUtils.FixDSize(privAsyKey.D.ToByteArrayUnsigned(), signParam.Q.X.Length);
			signParam.Validate();

			string signedToken = null;

			var signKey = ECDsa.Create(signParam);
			var b64PublicKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubAsyKey).GetEncoded().EncodeBase64();
			var handshakeJson = new HandshakeData
			{
				salt = secretPrepend.EncodeBase64(),
				signedToken = signedToken
			};
			string val = JWT.Encode(handshakeJson, signKey, JwsAlgorithm.ES384, new Dictionary<string, object> { { "x5u", b64PublicKey } });

			var response = new McbeServerToClientHandshake();
			response.token = val;
			SendPacket(response);
			
			CryptoContext.UseEncryption = true;
		}
	}
}
