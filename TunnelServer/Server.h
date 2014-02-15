#pragma once

#include "DataBase.h"

class TunnelServer : Net::server
{
public:
	TunnelServer(Net::net_manager *net_manager,
		int port, bool nonblocking, bool no_nagle_delay);
	~TunnelServer();

public: // Net::server
	virtual Net::i_net_member* create_connection(int socket);

private:
	class Node;

private:
	void register_client(int client_id, Node* connection);
	void unregister_client(int client_id);

private:
	std::map<int, Node*> clients_;
	DataBase db_;
};

class Server::Node : public Net::connection
{
public:
	Node(Server *own_server, int socket, DataBase *db);
	~Node();

public: // Net::connection
	virtual int process_events(short int polling_events);

private:
	int try_login();
	int process_packet();

	struct destination_node
	{
		int id_;
		int port_;
	};

	Server *own_server_;
	int node_id_;
	std::map<std::string, destination_node> destination_node_list_;
	TunnelCommon::ProtocolParser protocol_;
	DataBase *db_;
	bool is_logined_;
};

