#include "stdafx.h"

#include "DataBase.h"

#include "StringService.h"

namespace
{

const std::string query_connection_db = "dbname={dbname} host={host} user={user} password={password}";

const std::string tag_db_name = "{dbname}";
const std::string tag_db_host = "{host}";
const std::string tag_db_user = "{user}";
const std::string tag_db_password = "{password}";

const std::string db_name = "data_gate";
const std::string db_host = "localhost";
const std::string db_user = "postgres";
const std::string db_password = "12345";

} // namespace

DataBase::DataBase(const std::string& dbname,
	const std::string& host,
	const std::string& user,
	const std::string& password)
	: is_connected_(false)
{
	std::string connection_query = query_connection_db;
	StringService::Replace(connection_query, tag_db_name, db_name);
	StringService::Replace(connection_query, tag_db_host, db_host);
	StringService::Replace(connection_query, tag_db_user, db_user);
	StringService::Replace(connection_query, tag_db_password, db_password);

	conn = PQconnectdb(connection_query.c_str());

	if (PQstatus(conn) == CONNECTION_BAD)
	{
		is_connected_ = true;
	}
}

DataBase::~DataBase()
{
	PQfinish(conn);
}


