#pragma once

#include "DataBase.h"

class Node;

class ProtocolParser : public TunnelCommon::Protocol
{
public:

	ProtocolParser(Node *own_node);
	~ProtocolParser();

public: // Tunnelcommon::Protocol
	virtual int process_in();
	virtual int process_out();

	/*!
	 * Login packet format:
	 * 1.) Login length
	 * 2.) Login
	 * 3.) Password hash length
	 * 4.) Password hash
	 */
	int parse_login_packet();

private:
	DataBase db_;
	Node *own_node_;

	bool got_login_data_;
	std::vector<char> login_;
	std::vector<char> passwd_hash_;
	std::string node_name_;
};

