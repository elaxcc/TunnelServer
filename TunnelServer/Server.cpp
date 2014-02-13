#include "stdafx.h"

#include "Server.h"

namespace
{

const std::string db_name = "tunnel_db";
const std::string db_host = "localhost";
const std::string db_user = "postgres";
const std::string db_password = "12345";

} // namespace

Server::Server(Net::net_manager *net_manager,
	int port, bool nonblocking, bool no_nagle_delay)
	: Net::server(net_manager, port, nonblocking, no_nagle_delay)
	, db_(db_name, db_host, db_user, db_password)
{
}

Server::~Server()
{
}

void Server::register_client(int client_id, Server::ServerConnection* connection)
{
	if (client_id != 0)
	{
		clients_.insert(std::make_pair(client_id, connection));
	}
}

void Server::unregister_client(int client_id)
{
	std::map<int, Server::ServerConnection*>::iterator iter =
		clients_.find(client_id);
	if (iter != clients_.end())
	{
		clients_.erase(iter);
	}
}

Net::i_net_member* Server::create_connection(int socket)
{
	ServerConnection *new_client = new ServerConnection(this, socket, &db_);

	return new_client;
}

///////////////////////////////////////////////////////////////////////////

Server::ServerConnection::ServerConnection(Server *own_server, int socket,
	DataBase *db)
	: Net::connection(socket, Net::c_poll_event_in)
	, own_server_(own_server)
	, db_(db)
{
}

Server::ServerConnection::~ServerConnection()
{
	own_server_->unregister_client(id_);
}

int Server::ServerConnection::process_events(short int polling_events)
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
		if (protocol_.is_complete())
		{
			if (!protocol_.got_rsa_key())
			{
				// process external RSA public key

				parse_result = protocol_.parse_rsa_key_packet();
				if (parse_result == TunnelCommon::ProtocolParser::Error_no &&
					protocol_.got_rsa_key())
				{
					// send internal RSA public key
					std::vector<char> packet;
					parse_result = protocol_.prepare_rsa_internal_pub_key_packet(packet);
					if (parse_result == TunnelCommon::ProtocolParser::Error_no)
					{
						Net::send_data(get_socket(), &packet[0], packet.size());
					}
					else
					{
						//!fixme can't prepare packet with internal RSA public key
					}
				}
			}
			else if (!protocol_.got_login_data())
			{
				parse_result = protocol_.parse_login_packet();
				if (parse_result == TunnelCommon::ProtocolParser::Error_no &&
					protocol_.got_login_data())
				{
					// check login and passwd
					bool user_exist = db_->check_user_exist(
						protocol_.get_login(), protocol_.get_passwd_hash());
					if (user_exist)
					{
						// send login accept packet
						std::vector<char> accept_login_packet;
						protocol_.prepare_packet(
							TunnelCommon::ProtocolParser::c_user_accept_packet_,
							accept_login_packet);
						Net::send_data(get_socket(), &accept_login_packet[0],
							accept_login_packet.size());
					}
					else
					{
						return Net::error_connection_is_closed_;
					}
				}
			}
			else
			{
				//!fixme can't parse login data
			}
		}
		else
		{
			protocol_.flush_common();
		}
	}
	else
	{
		
	}

	return Net::error_no_;
}

