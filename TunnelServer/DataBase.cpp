#include "stdafx.h"

#include "DataBase.h"

namespace
{

const std::string query_connection_db = "dbname={dbname} host={host} user={user} password={password}";

const std::string tag_db_name = "{dbname}";
const std::string tag_db_host = "{host}";
const std::string tag_db_user = "{user}";
const std::string tag_db_password = "{password}";

const std::string query_check_user_exist =
	"SELECT users.id "
	"FROM users "
	"WHERE users.login = '{login}' AND users.passwd_hash = '{passwd_hash}'";

const std::string query_get_node_id_by_name =
	"SELECT nodes.id "
	"FROM nodes "
	"WHERE nodes.name = '{node_name}'";

const std::string query_get_nodes_list =
	"SELECT nodes.name "
	"FROM nodes "
	"WHERE nodes.user_id";

const std::string query_get_tunnels_list =
	"SELECT * "
	"FROM tunnels "
	"WHERE tunnels.first_node = {node_id} OR tunnels.second_node = {node_id}";

const std::string query_get_user_id_by_login =
	"SELECT users.id "
	"FROM users "
	"WHERE users.login = {user_login}";

const std::string query_get_nodes_names_list = 
	"SELECT nodes.name "
	"FROM nodes "
	"WHERE nodes.user_id = {user_id}";

const std::string tag_login = "{login}";
const std::string tag_passwd_hash = "{passwd_hash}";
const std::string tag_user_id = "{user_id}";
const std::string tag_node_id ="{node_id}";
const std::string tag_node_name = "{node_name}";
const std::string tag_user_login = "{user_login}";

} // namespace

DataBase::DataBase(const std::string& db_name,
	const std::string& db_host,
	const std::string& db_user,
	const std::string& db_password)
	: is_connected_(false)
{
	std::string connection_query = query_connection_db;
	StringService::Replace(connection_query, tag_db_name, db_name);
	StringService::Replace(connection_query, tag_db_host, db_host);
	StringService::Replace(connection_query, tag_db_user, db_user);
	StringService::Replace(connection_query, tag_db_password, db_password);

	conn_ = PQconnectdb(connection_query.c_str());

	if (PQstatus(conn_) == CONNECTION_BAD)
	{
		is_connected_ = true;
	}
}

DataBase::~DataBase()
{
	PQfinish(conn_);
}

bool DataBase::make_query(const std::string& query)
{
	PQclear(res_);

	res_ = PQexec(conn_, query.c_str());

	if (PQresultStatus(res_) != PGRES_TUPLES_OK)
	{
		return false;
	}
}

bool DataBase::check_user_exist(const std::vector<char>& login,
	const std::vector<char>& passwd_hash)
{
	std::string query = query_check_user_exist;
	std::string str_login(&login[0], login.size());
	std::string str_passwd_hash(&passwd_hash[0], passwd_hash.size());
	StringService::Replace(query, tag_login, str_login);
	StringService::Replace(query, tag_passwd_hash, str_passwd_hash);

	if (make_query(query))
	{
		return PQntuples(res_) == 1;
	}
	return false;
}

bool DataBase::get_user_id_by_login(const std::string& user_login, int *user_id)
{
	std::string query = query_get_user_id_by_login;
	StringService::Replace(query, tag_node_name, user_login);

	if (make_query(query) && (PQntuples(res_) > 0))
	{
		*user_id = boost::lexical_cast<int>(PQgetvalue(res_, 0, 0));
		return true;
	}
	return false;
}

bool DataBase::get_node_id_by_name(const std::string& node_name, int *out_node_id)
{
	std::string query = query_get_node_id_by_name;
	StringService::Replace(query, tag_node_name, node_name);

	if (make_query(query) && (PQntuples(res_) > 0))
	{
		*out_node_id = boost::lexical_cast<int>(PQgetvalue(res_, 0, 0));
		return true;
	}
	return false;
}

bool DataBase::get_nodes_list(int user_id, std::list<std::string>& nodes_list)
{
	std::string query = query_get_nodes_list;
	std::stringstream ss;
	ss << user_id;
	StringService::Replace(query, tag_login, ss.str());

	if (make_query(query))
	{
		int rec_count = PQntuples(res_);
		if (rec_count == 0)
		{
			return false;
		}
		for (int i = 0; i < rec_count; ++i)
		{
			std::string node_name = PQgetvalue(res_, i, 0);
			nodes_list.push_back(node_name);
		}
		return true;
	}
	return false;
}

bool DataBase::get_tunnels_list(int node_id, std::list<Tunnel> tunnels)
{
	std::string query = query_get_tunnels_list;
	std::stringstream ss;
	ss << node_id;
	StringService::Replace(query, tag_node_id, ss.str());

	if (make_query(query))
	{
		int rec_count = PQntuples(res_);
		if (rec_count == 0)
		{
			return false;
		}

		for (int i = 0; i < rec_count; ++i)
		{
			int id = boost::lexical_cast<int>(PQgetvalue(res_, i, 0));
			std::string name = PQgetvalue(res_, i, 1);
			int first_node = boost::lexical_cast<int>(PQgetvalue(res_, i, 2));
			int first_port =boost::lexical_cast<int>(PQgetvalue(res_, i, 3));
			int second_node = boost::lexical_cast<int>(PQgetvalue(res_, i, 4));
			int second_port =boost::lexical_cast<int>(PQgetvalue(res_, i, 5));

			tunnels.push_back(Tunnel(
				id,
				name,
				first_node,
				(short) first_port,
				second_node,
				(short) second_port));
		}
		return true;
	}
	return false;
}

bool DataBase::get_node_names_list(int user_id, std::list<std::string>& node_names_list)
{
	std::string query = query_get_nodes_names_list;
	StringService::Replace(query, tag_user_id, boost::lexical_cast<std::string>(user_id));

	if (make_query(query))
	{
		int rec_count = PQntuples(res_);
		if (rec_count == 0)
		{
			return false;
		}
		for (int i = 0; i < rec_count; i++)
		{
			std::string node_name = PQgetvalue(res_, i, 0);
			node_names_list.push_back(node_name);
		}
		return true;
	}
	return false;
}
