#include "stdafx.h"

#include "Server.h"

int _tmain(int argc, _TCHAR* argv[])
{
	Net::init();

	c_Debug() << "Tunnel server started" << "\r\n";

	Net::net_manager net_manager;
	TunnelServer tunnel_server(&net_manager, 1234, true, true);

	net_manager.add_member(&tunnel_server);

	while (true)
	{
		net_manager.process_sockets();
	}

	return 0;
}

