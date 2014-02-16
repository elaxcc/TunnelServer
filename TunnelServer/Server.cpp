#include "stdafx.h"

#include "Server.h"

TunnelServer::TunnelServer(Net::net_manager *net_manager,
	int port, bool nonblocking, bool no_nagle_delay)
	: Net::server(net_manager, port, nonblocking, no_nagle_delay)
{
}

TunnelServer::~TunnelServer()
{
}

void TunnelServer::register_client(int client_id, Node* connection)
{
	if (client_id != 0)
	{
		clients_.insert(std::make_pair(client_id, connection));
	}
}

void TunnelServer::unregister_client(int client_id)
{
	std::map<int, Node*>::iterator iter =
		clients_.find(client_id);
	if (iter != clients_.end())
	{
		clients_.erase(iter);
	}
}

Net::i_net_member* TunnelServer::create_connection(int socket)
{
	Node *new_client = new Node(this, socket);

	return new_client;
}

///////////////////////////////////////////////////////////////////////////

Node::Node(TunnelServer *own_server, int socket)
	: Net::connection(socket, Net::c_poll_event_in)
	, own_server_(own_server)
	, is_logined_(false)
	, node_id_(0)
{
	protocol_ = new ProtocolParser(this);
}

Node::~Node()
{
	delete protocol_;
	own_server_->unregister_client(node_id_);
}

int Node::process_events(short int polling_events)
{
	if (polling_events == Net::c_poll_event_in)
	{
		// receive data from socket
		std::vector<char> recv_data;
		int recv_result = Net::recv_all(get_socket(), recv_data);
		if (recv_result == Net::error_connection_is_closed_)
		{
			return Net::error_connection_is_closed_;
		}

		// parse packet
		int parse_result = protocol_->parse_common(recv_data);
		if (protocol_->is_complete())
		{
			protocol_->process_packet();
		}
	}
	else
	{
	}

	return Net::error_no_;
}

void Node::set_node_id(int node_id)
{
	node_id_ = node_id;
	own_server_->register_client(node_id_, this);
}

