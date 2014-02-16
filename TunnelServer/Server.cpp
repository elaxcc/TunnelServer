#include "stdafx.h"

#include "Server.h"

namespace
{

const std::string db_name = "tunnel_db";
const std::string db_host = "localhost";
const std::string db_user = "postgres";
const std::string db_password = "12345";

} // namespace

TunnelServer::TunnelServer(Net::net_manager *net_manager,
	int port, bool nonblocking, bool no_nagle_delay)
	: Net::server(net_manager, port, nonblocking, no_nagle_delay)
	, db_(db_name, db_host, db_user, db_password)
{
}

TunnelServer::~TunnelServer()
{
}

void TunnelServer::register_client(int client_id, TunnelServer::Node* connection)
{
	if (client_id != 0)
	{
		clients_.insert(std::make_pair(client_id, connection));
	}
}

void TunnelServer::unregister_client(int client_id)
{
	std::map<int, TunnelServer::Node*>::iterator iter =
		clients_.find(client_id);
	if (iter != clients_.end())
	{
		clients_.erase(iter);
	}
}

Net::i_net_member* TunnelServer::create_connection(int socket)
{
	Node *new_client = new Node(this, socket, &db_);

	return new_client;
}

///////////////////////////////////////////////////////////////////////////

TunnelServer::Node::Node(TunnelServer *own_server, int socket,
	DataBase *db)
	: Net::connection(socket, Net::c_poll_event_in)
	, own_server_(own_server)
	, db_(db)
	, is_logined_(false)
	, node_id_(0)
{
}

TunnelServer::Node::~Node()
{
	own_server_->unregister_client(node_id_);
}

int TunnelServer::Node::process_events(short int polling_events)
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
		int parse_result = protocol_.parse_common(recv_data);
		if (!is_logined_)
		{
			try_login();
		}
		else
		{
			process_packet();
		}
	}
	else
	{
		
	}

	return Net::error_no_;
}

int TunnelServer::Node::try_login()
{
	int parse_result = ProtocolParser::Error_no;

	if (!protocol_.got_rsa_key())
	{
		// process external RSA public key

		if (protocol_.parse_rsa_key_packet() == ProtocolParser::Error_no)
		{
			// send internal RSA public key
			std::vector<char> packet;
			parse_result = protocol_.prepare_rsa_internal_pub_key_packet(packet);
			if (parse_result == ProtocolParser::Error_no)
			{
				Net::send_data(get_socket(), &packet[0], packet.size());
				return Net::error_no_;
			}
		}
		return Net::error_connection_is_closed_;
	}
	else if (!protocol_.got_login_data())
	{
		if (protocol_.parse_login_packet() == ProtocolParser::Error_no)
		{
			// check login and passwd
			bool user_exist = db_->check_user_exist(protocol_.get_login(), protocol_.get_passwd_hash());
			if (user_exist)
			{
				// get node ID by name
				if (!protocol_.get_node_name().empty())
				{
					if (db_->get_node_id_by_name(protocol_.get_node_name(), &node_id_))
					{
						own_server_->register_client(node_id_, this);
					}
				}

				// send login accept packet
				std::vector<char> accept_login_packet;
				protocol_.prepare_packet(
					ProtocolParser::c_user_accept_packet_,
					accept_login_packet);
				Net::send_data(get_socket(), &accept_login_packet[0],
					accept_login_packet.size());

				is_logined_ = true;

				return Net::error_no_;
			}
		}
		return Net::error_connection_is_closed_;
	}
	return Net::error_no_;
}

int TunnelServer::Node::process_packet()
{
	return Net::error_no_;
}

