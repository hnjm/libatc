#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <zlib.h>

#include "Rijndael.h"
#include "ATCCommon.h"

using namespace std;

class ATCUnlocker
{
public:
	ATCUnlocker();
	~ATCUnlocker();

	ATCResult	open(istream *src, const char key[ATC_KEY_SIZE]);
	ATCResult	close();

	size_t		getEntryLength() const;
	ATCResult	getEntry(ATCFileEntry *entry, size_t index);
	ATCResult	extractFileData(ostream *dst, istream *src, size_t length);

public:
	int32_t data_version()		const;
	char	data_sub_version()	const;
	int32_t algorism_type()		const;
	char	passwd_try_limit()	const;
	bool	self_destruction()	const;

private:
	void	decryptBuffer(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE]);
	bool	parseFileEntry(ATCFileEntry *entry, const std::string& tsv_sjis, const std::string& tsv_utf8 = "");

private:
	int32_t data_version_;
	char	data_sub_version_;
	int32_t algorism_type_;
	char	passwd_try_limit_;
	bool	self_destruction_;
	string	create_date_string_;
	
	int64_t total_length_;
	int64_t total_read_length_;

	CRijndael rijndael_;
	char chain_buffer_[ATC_BUF_SIZE];

	z_stream z_;
	int32_t z_flush_, z_status_;
	char input_buffer_[ATC_BUF_SIZE];
	char output_buffer_[ATC_LARGE_BUF_SIZE];
	string tmp_buffer_;

	vector<ATCFileEntry> entries_;
};