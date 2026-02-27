using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using ATRI.dot_raknet.Network;
using ATRI.Global;
using ATRI.https;
using ATRI.XBOX;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Protocol.Network;
using Protocol.Utils;
using Protocol.Utils.Crypto;
using SharpRakNet.Network;

using Logger = Protocol.Logger;


namespace ATRI
{
	internal class Program
	{
		public static MinecraftStyleJwtGenerator generator = new MinecraftStyleJwtGenerator();
		public static AsymmetricCipherKeyPair key = CryptoUtils.GenerateClientKey();
		public static string Token = string.Empty;
		static void Main(string[] args)
		{
			
			XBOXService.StartLoginEach().Wait();
			if (XBOXService.Users.Count == 0)
			{
				XBOXService.AddUser().Wait();
			}
			
			foreach (var user in XBOXService.Users)
			{
				var result = XBOXService.XboxLive(user.Value).Result;
				var base64 = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key.Public).GetEncoded().EncodeBase64();
				var s = XBOXService.GetSignedToken(result,base64).Result;
				Token = s;
			}
			KestrelHttpsServer.JwkKeys.AddRange(generator._keyManager.GetAllJwkKeys());
			var raknetListener = new RaknetListener(IPEndPoint.Parse("0.0.0.0:19138"));
			raknetListener.BeginListener();
			Logger.info("Back Server Started!");
			const string domain = "client.discovery.minecraft-services.net";
			const int port = 443;

			if (!File.Exists($"{domain}.pfx"))
			{
				CertificateCreator.CreateSelfSignedCertificate(domain);
				var installer = new CertificateManager();
				installer.InstallCertificateToLocalMachineRoot("client.discovery.minecraft-services.net.cer");
			}
			var server = new KestrelHttpsServer(domain, port);
			server.Start();
			Console.ReadKey();
		}
	}
}