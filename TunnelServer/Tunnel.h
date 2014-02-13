#pragma once

struct Tunnel
{
	Tunnel(int id, const std::string& name,
		int first_node_id, short first_port,
		int second_node_id, short second_port)
		: id_(id)
		, name_(name)
		, first_node_id_(first_node_id)
		, first_port_(first_port)
		, second_node_id_(second_node_id)
		, second_port_(second_port)
	{
	}

	~Tunnel()
	{
		name_.clear();
	}

	int id_;
	std::string name_;
	int first_node_id_;
	short first_port_;
	int second_node_id_;
	short second_port_;
};

