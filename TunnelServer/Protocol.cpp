#include "stdafx.h"

#include "Protocol.h"

ProtocolParser::ProtocolParser()
	: got_data_len_(false)
	, got_data_(false)
	, got_crc_(false)
	, complete_(false)
{
}

ProtocolParser::~ProtocolParser()
{
	buffer_.clear();
	data_.clear();
}

void ProtocolParser::parse(const std::vector<char>& data)
{
	buffer_.insert(buffer_.end(), data.begin(), data.end());

	if (complete_)
	{
		return;
	}

	if (!got_data_len_)
	{
		if (buffer_.size() < sizeof(boost::uint32_t))
		{
			return;
		}

		data_len_ = 0x000000FF & buffer_[0];
		data_len_ = data_len_ | (0x0000FF00 & (buffer_[1] << 8));
		data_len_ = data_len_ | (0x00FF0000 & (buffer_[2] << 16));
		data_len_ = data_len_ | (0xFF000000 & (buffer_[3] << 24));

		buffer_.erase(buffer_.begin(), buffer_.begin() + sizeof(data_len_));
		got_data_len_ = true;
	}

	if (!got_data_)
	{
		if (buffer_.size() < data_len_)
		{
			return;
		}

		data_.insert(data_.begin(), buffer_.begin(), buffer_.end());
		buffer_.erase(buffer_.begin(), buffer_.begin() + data_len_);
		got_data_ = true;

		crc_calc_.Update(data_);
	}

	if (!got_crc_)
	{
		if (buffer_.size() < sizeof(crc_))
		{
			return;
		}

		crc_ = 0x000000FF & buffer_[0];
		crc_ = crc_ | (0x0000FF00 & (buffer_[1] << 8));
		crc_ = crc_ | (0x00FF0000 & (buffer_[2] << 16));
		crc_ = crc_ | (0xFF000000 & (buffer_[3] << 24));

		got_crc_ = true;

		crc_calc_.Final();
		boost::uint32_t calculated_crc = crc_calc_.GetHash();

		if (calculated_crc == crc_)
		{
			complete_ = true;
		}
	}
}

void ProtocolParser::flush()
{
	got_data_len_ = false;
	got_data_ = false;
	got_crc_ = false;
	complete_ = false;

	crc_calc_.Clean();
	data_.clear();
}

void ProtocolParser::reset()
{
	flush();
	buffer_.clear();
}

void ProtocolParser::parse_login_data()
{
	boost::uint32_t shift = 0;

	// login length
	boost::uint32_t login_length;
	login_length = 0x000000FF & data_[0];
	login_length = login_length | (0x0000FF00 & (data_[1] << 8));
	login_length = login_length | (0x00FF0000 & (data_[2] << 16));
	login_length = login_length | (0xFF000000 & (data_[3] << 24));
	shift += sizeof(login_length);

	// login
	std::vector<char> login;
	login.insert(login.begin(), data_[shift],
		data_[shift] + login_length);
	shift += login_length;

	// password length
	boost::uint32_t passwd_length;
	passwd_length = 0x000000FF & data_[shift];
	passwd_length = passwd_length | (0x0000FF00 & (data_[shift + 1] << 8));
	passwd_length = passwd_length | (0x00FF0000 & (data_[shift + 2] << 16));
	passwd_length = passwd_length | (0xFF000000 & (data_[shift + 3] << 24));
	shift += sizeof(passwd_length);

	// password
	std::vector<char> passwd;
	passwd.insert(passwd.begin(), data_[shift],
		data_[shift] + passwd_length);

	//!fixme check login and password
}
