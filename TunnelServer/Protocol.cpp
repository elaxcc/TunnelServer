#include "stdafx.h"

#include "Protocol.h"

#include "Server.h"

namespace
{

const std::string db_name = "tunnel_db";
const std::string db_host = "localhost";
const std::string db_user = "postgres";
const std::string db_password = "12345";

const std::string packet_user_accept = "Hello user!!!";

} // namespace

ProtocolParser::ProtocolParser(Node *own_node)
	: got_login_data_(false)
	, db_(db_name, db_host, db_user, db_password)
	, own_node_(own_node)
{
}

ProtocolParser::~ProtocolParser()
{
	reset();
}

int ProtocolParser::process_in()
{
	if (!is_complete())
	{
		return Error_packet_not_complete;
	}

	switch (get_packet_type())
	{
	case Packet_type_external_rsa_key :
		{
			c_Debug() << "process packet, type == 'Packet_type_external_rsa_key'" << "\r\n";

			if (!got_rsa_key())
			{
				// process external RSA public key
				if (parse_external_rsa_key_packet() == ProtocolParser::Error_no)
				{
					// send internal RSA public key
					std::vector<char> packet;
					int parse_result = prepare_rsa_internal_pub_key_packet(packet);
					if (parse_result == ProtocolParser::Error_no)
					{
						Net::send_data(own_node_->get_socket(), &packet[0], packet.size());
						c_Debug() << "process packet, type == 'Packet_type_external_rsa_key', OK" << "\r\n";
						return Error_no;
					}
				}
				c_Debug() << "process packet, type == 'Packet_type_external_rsa_key', Error_rsa_key_packet" << "\r\n";
				return Error_rsa_key_packet;
			}
			break;
		}
	case Packet_type_login_data :
		{
			c_Debug() << "process packet, type == 'Packet_type_login_data'" << "\r\n";

			if (!got_login_data_)
			{
				if (parse_login_packet() == ProtocolParser::Error_no)
				{
					// check login and passwd
					bool user_exist = db_.check_user_exist(login_, passwd_hash_);
					if (user_exist)
					{
						// get user ID by login
						int user_id;
						db_.get_user_id_by_login(&user_id);
						own_node_->set_user_id(user_id);

						// get node ID by name
						if (!node_name_.empty())
						{
							int node_id = 0;
							if (db_.get_node_id_by_name(node_name_, &node_id))
							{
								own_node_->set_node_id(node_id);
							}
						}

						// send login accept packet
						std::vector<char> accept_login_packet;
						prepare_packet(Packet_type_login_accept, packet_user_accept,
							accept_login_packet);
						Net::send_data(own_node_->get_socket(), &accept_login_packet[0],
							accept_login_packet.size());

						c_Debug() << "process packet, type == 'Packet_type_login_data', OK" << "\r\n";
						return Error_no;
					}
					c_Debug() << "process packet, type == 'Packet_type_login_data', Error_parse_login_node_not_exist" << "\r\n";
					return Error_parse_login_node_not_exist;
				}
				c_Debug() << "process packet, type == 'Packet_type_login_data', Error_parse_login_packet" << "\r\n";
				return Error_parse_login_packet;
			}
			break;
		}
	default:
		{
			c_Debug() << "process packet, Error_unknown_packet" << "\r\n";
			flush();
			return Error_unknown_packet;
		}
	}
	flush();
	return Error_no;
}

int ProtocolParser::process_out()
{
	return Error_no;
}

int ProtocolParser::parse_login_packet()
{
	if (!is_complete())
	{
		return Error_packet_not_complete;
	}

	login_.clear();
	passwd_hash_.clear();
	got_login_data_ = false;

	boost::uint32_t processed_data = 0;

	const std::vector<char>& data = get_data();

	// login length
	boost::uint32_t login_length;
	login_length = 0x000000FF & data[0];
	login_length = login_length | (0x0000FF00 & (data[1] << 8));
	login_length = login_length | (0x00FF0000 & (data[2] << 16));
	login_length = login_length | (0xFF000000 & (data[3] << 24));
	processed_data += sizeof(login_length);

	if (login_length + sizeof(login_length) >= get_data().size())
	{
		return Error_parse_login_packet;
	}

	// login
	login_.insert(login_.begin(), &data[processed_data],
		&data[processed_data] + login_length);
	processed_data += login_length;

	// password length
	boost::uint32_t passwd_length;
	passwd_length = 0x000000FF & data[processed_data];
	passwd_length = passwd_length | (0x0000FF00 & (data[processed_data + 1] << 8));
	passwd_length = passwd_length | (0x00FF0000 & (data[processed_data + 2] << 16));
	passwd_length = passwd_length | (0xFF000000 & (data[processed_data + 3] << 24));
	processed_data += sizeof(passwd_length);

	if ((login_length + sizeof(login_length) + passwd_length  + sizeof(passwd_length)) > get_data().size())
	{
		return Error_parse_login_packet;
	}

	// password
	passwd_hash_.insert(passwd_hash_.begin(), &data[processed_data],
		&data[processed_data] + passwd_length);
	processed_data += passwd_length;

	// node name length
	boost::uint32_t node_name_length;
	node_name_length = 0x000000FF & data[processed_data];
	node_name_length = node_name_length | (0x0000FF00 & (data[processed_data + 1] << 8));
	node_name_length = node_name_length | (0x00FF0000 & (data[processed_data + 2] << 16));
	node_name_length = node_name_length | (0xFF000000 & (data[processed_data + 3] << 24));
	processed_data += sizeof(node_name_length);

	if ((login_length + sizeof(login_length) + 
		passwd_length  + sizeof(passwd_length) +
		node_name_length + sizeof(node_name_length)) > get_data().size())
	{
		return Error_parse_login_packet;
	}

	if (node_name_length != 0)
	{
		node_name_.insert(0, &data[processed_data], node_name_length);
	}

	got_login_data_ = true;

	return Error_no;
}
