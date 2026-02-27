using System;
using System.Collections.Generic;
using System.Text;
using ATRI.dot_raknet.Network;
using Protocol.Network;

namespace ATRI.Global
{
	public static class GlobalEvent
	{
		public static Func<MinecraftClient, Packet, Packet>? OnClientPacketReceive;
		public static Func<ServerSwitcher, Packet, Packet>? OnServerPacketReceive;

		public delegate void ClientRaknetConnected(MinecraftClient client);
		public static ClientRaknetConnected? OnClientRaknetConnected = delegate { } ;

		public delegate void ClientRaknetDisConnected(MinecraftClient client);
		public static ClientRaknetDisConnected? OnClientRaknetDisConnected = delegate { };

		public delegate void ClientMCConnected(MinecraftClient client);
		public static ClientMCConnected? OnClientMCConnected = delegate { };

		public delegate void ClientMCDisConnected(MinecraftClient client);
		public static ClientMCDisConnected? OnClientMCDisConnected = delegate { };


		

	}
}
