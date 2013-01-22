#include <cassert>
#include <ctime>
#include <fstream>
#include <sstream>
#include <vector>

#include <zlib.h>

#include "Rijndael.h"
#include "isaac.h"

#include "ATCCommon.h"

#ifdef unix
#undef unix
#endif


class ATCLocker_impl
{
public:
	ATCLocker_impl();
	~ATCLocker_impl();

	ATCResult open(ostream *dst, const char key[ATC_KEY_SIZE]);
	ATCResult close();

	ATCResult addFileEntry(const ATCFileEntry& entry);
	ATCResult writeEncryptedHeader(ostream *dst);
	ATCResult writeFileData(ostream *dst, istream *src, size_t length);

public:
	char passwd_try_limit() const;
	bool self_destruction() const;
	int32_t compression_level() const;
	time_t create_time() const;

	void set_passwd_try_limit(char passwd_try_limit);
	void set_self_destruction(bool self_destruction);
	void set_compression_level(int32_t compression_level);
	void set_create_time(time_t create_time);

private:
	void fillrand(char *buf, const int len);
	void getCurrentDateString(string *dst);
	void encryptBuffer(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE]);
	ATCResult finish();

private:
	char passwd_try_limit_;
	bool self_destruction_;
	int32_t compression_level_;

	int64_t total_length_;
	int64_t total_write_length_;

	CRijndael rijndael_;
	char chain_buffer_[ATC_BUF_SIZE];

	z_stream z_;
	int32_t z_flush_, z_status_;
	char input_buffer_[ATC_BUF_SIZE];
	char output_buffer_[ATC_BUF_SIZE];
	string tmp_buffer_;

	bool finished_;
	time_t create_time_;

	vector<ATCFileEntry> entries_;
};