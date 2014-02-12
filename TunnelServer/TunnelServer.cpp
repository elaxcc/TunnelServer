#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
	char data[] = "passwd";

	TunnelCommon::Md5_Hash md;

	md.Init();
	md.Update(data, 6);
	md.Final();
	std::vector<char> hash = md.GetHash();

	md.Clean();
	md.Init();
	md.Update(hash);
	md.Final();
	hash = md.GetHash();

	std::string str;
	for (int i = 0; i < hash.size(); ++i)
	{
		str = str + StringService::CharToHexStr(hash[i]);
	}

	return 0;
}

