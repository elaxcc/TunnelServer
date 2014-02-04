#pragma once

#include "NetCommon.h"

class Server : Net::server
{
public:
	Server(Net::net_manager *net_manager,
		int port, bool nonblocking, bool no_nagle_delay);
	~Server();

public: // Net::server
	virtual Net::i_net_member* create_connection(int socket);

private:
	class ServerConnection;

private:
	void register_client(const std::string& client_id, ServerConnection* connection);
	void unregister_client(const std::string& client_id);

private:
	std::map<std::string, ServerConnection*> clients_;
};

class Server::ServerConnection : public Net::connection
{
public:
	ServerConnection(Server *own_server, int socket);
	~ServerConnection();

public: // Net::connection
	virtual int process_events(short int polling_events);

private:
	struct destination_node
	{
		std::string id_;
		int port_;
	};

	Server *own_server_;
	std::string id_;
	std::map<std::string, destination_node> destination_node_list_;
};

