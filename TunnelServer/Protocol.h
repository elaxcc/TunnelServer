#pragma once

class ProtocolParser
{
public:
	ProtocolParser();
	~ProtocolParser();

	void parse(const std::vector<char>& data);
	void flush();
	void reset();

	/*!
	 * Login packet format:
	 * 1.) Login length
	 * 2.) Login
	 * 3.) Password hash length
	 * 4.) Password hash
	 */
	void parse_login_data();

private:
	TunnelCommon::RsaCrypting rsa_crypting_;
	TunnelCommon::CRC32_hash crc_calc_;
	std::vector<char> buffer_;

	bool got_data_len_;
	bool got_data_;
	bool got_crc_;
	bool complete_;

	boost::uint32_t data_len_;
	std::vector<char> data_;
	boost::uint32_t crc_;
};
