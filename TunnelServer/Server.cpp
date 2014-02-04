#include "stdafx.h"

#include "Server.h"

Server::Server(Net::net_manager *net_manager,
	int port, bool nonblocking, bool no_nagle_delay)
	: Net::server(net_manager, port, nonblocking, no_nagle_delay)
{
}

Server::~Server()
{
}

void Server::register_client(const std::string& client_id, Server::ServerConnection* connection)
{
	if (!client_id.empty())
	{
		clients_.insert(std::make_pair(client_id, connection));
	}
}

void Server::unregister_client(const std::string& client_id)
{
	std::map<std::string, Server::ServerConnection*>::iterator iter =
		clients_.find(client_id);
	if (iter != clients_.end())
	{
		clients_.erase(iter);
	}
}

Net::i_net_member* Server::create_connection(int socket)
{
	ServerConnection *new_client = new ServerConnection(this, socket);

	return new_client;
}

///////////////////////////////////////////////////////////////////////////

Server::ServerConnection::ServerConnection(Server *own_server, int socket)
	: Net::connection(socket, Net::c_poll_event_in)
	, own_server_(own_server)
{
}

Server::ServerConnection::~ServerConnection()
{
}

int Server::ServerConnection::process_events(short int polling_events)
{
	return Net::error_no_;
}

