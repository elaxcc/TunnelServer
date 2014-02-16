#ifndef _DATABASE_H_
#define _DATABASE_H_

#include "Tunnel.h"

class DataBase
{
public:
	DataBase(const std::string& db_name,
		const std::string& db_host,
		const std::string& db_user,
		const std::string& db_password);
	~DataBase();

	bool is_connected() {return is_connected_;}

	bool check_user_exist(const std::vector<char>& login,
		const std::vector<char>& passwd_hash);
	bool get_node_id_by_name(const std::string& node_name, int *out_node_id);
	bool get_nodes_list(int user_id, std::list<std::string>& nodes_list);
	bool get_tunnels_list(int node_id, std::list<Tunnel> tunnels);

private:
	PGconn *conn;
	PGresult *res;
	bool is_connected_;
};

#endif // _DATABASE_H_
