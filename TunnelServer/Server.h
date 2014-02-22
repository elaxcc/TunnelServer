#pragma once

#include "DataBase.h"
#include "Protocol.h"

class TunnelServer : public Net::server
{
public:
	TunnelServer(Net::net_manager *net_manager,
		int port, bool nonblocking, bool no_nagle_delay);
	~TunnelServer();

public: // Net::server
	virtual Net::i_net_member* create_connection(int socket);

	void register_client(int client_id, Node* connection);
	void unregister_client(int client_id);

private:
	std::map<int, Node*> clients_;
};

class Node : public Net::connection
{
public:
	Node(TunnelServer *own_server, int socket);
	~Node();

public: // Net::connection
	virtual int process_events(short int polling_events);
	void set_node_id(int node_id);
	void set_user_id(int user_id);

private:

	struct destination_node
	{
		int id_;
		int port_;
	};

	TunnelServer *own_server_;
	int node_id_;
	int user_id_;
	std::map<std::string, destination_node> destination_node_list_;
	ProtocolParser *protocol_;
};

