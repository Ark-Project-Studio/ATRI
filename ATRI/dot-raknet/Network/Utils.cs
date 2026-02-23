using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ATRI.dot_raknet.Network
{
	public static class JwtUtils
	{
		public static (long iat, long exp, long nbf) GenerateJwtTimes(int validityHours = 24)
		{
			DateTime now = DateTime.UtcNow;

			long iat = new DateTimeOffset(now).ToUnixTimeSeconds();
			long nbf = iat;  // 通常与 iat 相同，表示立即生效
			long exp = new DateTimeOffset(now.AddHours(validityHours)).ToUnixTimeSeconds();

			return (iat, exp, nbf);
		}
		private static string SignJwt(Dictionary<string, object> header, Dictionary<string, object> payload,
			AsymmetricKeyParameter privateKey, string algorithm)
		{
			var headerJson = JsonSerializer.Serialize(header);
			var payloadJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions
			{
				PropertyNamingPolicy = JsonNamingPolicy.CamelCase
			});

			var headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
			var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

			var dataToSign = $"{headerBase64}.{payloadBase64}";

			byte[] signature = algorithm.ToUpper() switch
			{
				"RS256" => SignRsaSha256(dataToSign, privateKey as RsaKeyParameters),
				"ES384" => SignEcdsaSha384(dataToSign, privateKey as ECPrivateKeyParameters),
				_ => throw new ArgumentException($"不支持的算法: {algorithm}")
			};

			var signatureBase64 = Base64UrlEncode(signature);
			return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
		}
		private static string Base64UrlEncode(byte[] input)
		{
			var base64 = Convert.ToBase64String(input);
			return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
		}

		private static byte[] SignRsaSha256(string data, RsaKeyParameters privateKey)
		{
			var signer = SignerUtilities.GetSigner("SHA256withRSA");
			signer.Init(true, privateKey);
			var bytes = Encoding.UTF8.GetBytes(data);
			signer.BlockUpdate(bytes, 0, bytes.Length);
			return signer.GenerateSignature();
		}

		private static byte[] SignEcdsaSha384(string data, ECPrivateKeyParameters privateKey)
		{
			var signer = SignerUtilities.GetSigner("SHA384withECDSA");
			signer.Init(true, privateKey);
			var bytes = Encoding.UTF8.GetBytes(data);
			signer.BlockUpdate(bytes, 0, bytes.Length);
			return signer.GenerateSignature();
		}
	}
}
