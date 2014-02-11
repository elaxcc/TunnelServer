#ifndef _DATABASE_H_
#define _DATABASE_H_

class DataBase
{
public:
	DataBase(const std::string& dbname,
		const std::string& host,
		const std::string& user,
		const std::string& password);
	~DataBase();

	bool is_connected() {return is_connected_;}

private:
	PGconn *conn;
	PGresult *res;
	bool is_connected_;
};

#endif // _DATABASE_H_
