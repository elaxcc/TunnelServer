#pragma once

#include "DataBase.h"

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
	void register_client(int client_id, ServerConnection* connection);
	void unregister_client(int client_id);

private:
	std::map<int, ServerConnection*> clients_;
	DataBase db_;
};

class Server::ServerConnection : public Net::connection
{
public:
	ServerConnection(Server *own_server, int socket, DataBase *db);
	~ServerConnection();

public: // Net::connection
	virtual int process_events(short int polling_events);

private:
	struct destination_node
	{
		int id_;
		int port_;
	};

	Server *own_server_;
	int id_;
	std::map<std::string, destination_node> destination_node_list_;
	TunnelCommon::ProtocolParser protocol_;
	DataBase *db_;
};

