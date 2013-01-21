#include <cassert>
#include <ctime>
#include <fstream>
#include <sstream>
#include <vector>

#include <zlib.h>

#include "Rijndael.h"
#include "isaac.h"

#include "ATCCommon.h"
#include "ATCLocker.h"

#ifdef unix
#undef unix
#endif



//
// Implementation definition
//


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

	void set_passwd_try_limit(char passwd_try_limit);
	void set_self_destruction(bool self_destruction);
	void set_compression_level(int32_t compression_level);

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

	vector<ATCFileEntry> entries_;
};



//
// Interface
//


ATCLocker::ATCLocker() :

impl_(NULL)

{
	impl_ = new ATCLocker_impl();
}

ATCLocker::~ATCLocker()
{
	if (impl_)
	{
		delete impl_;
		impl_ = NULL;
	}
}

ATCResult ATCLocker::open(ostream *dst, const char key[ATC_KEY_SIZE])
{
	return impl_->open(dst, key);
}

ATCResult ATCLocker::close()
{
	return impl_->close();
}

ATCResult ATCLocker::addFileEntry(const ATCFileEntry& entry)
{
	return impl_->addFileEntry(entry);
}

ATCResult ATCLocker::writeEncryptedHeader(ostream *dst)
{
	return impl_->writeEncryptedHeader(dst);
}

ATCResult ATCLocker::writeFileData(ostream *dst, istream *src, size_t length)
{
	return impl_->writeFileData(dst, src, length);
}

char ATCLocker::passwd_try_limit() const
{
	return impl_->passwd_try_limit();
}

bool ATCLocker::self_destruction() const
{
	return impl_->self_destruction();
}

int32_t ATCLocker::compression_level() const
{
	return impl_->compression_level();
}

void ATCLocker::set_passwd_try_limit(char passwd_try_limit)
{
	impl_->set_passwd_try_limit(passwd_try_limit);
}

void ATCLocker::set_self_destruction(bool self_destruction)
{
	impl_->set_self_destruction(self_destruction);
}

void ATCLocker::set_compression_level(int32_t compression_level)
{
	impl_->set_compression_level(compression_level);
}



//
// Implementation
//


ATCLocker_impl::ATCLocker_impl() :

passwd_try_limit_(ATC_DEFAULT_PASSWORD_TRY_LIMIT),
self_destruction_(false),
compression_level_(Z_DEFAULT_COMPRESSION),

total_length_(0),
total_write_length_(0),

finished_(false)

{
}


ATCLocker_impl::~ATCLocker_impl()
{
	close();
}

ATCResult ATCLocker_impl::open(ostream *dst, const char key[ATC_KEY_SIZE])
{
	const char zero[ATC_KEY_SIZE] = {0};
	if (memcmp(zero, key, ATC_KEY_SIZE) == 0)
	{
		return ATC_ERR_NULL_KEY;
	}

	const char null[] = {0, 0, 0, 0};
	const char data_sub_version = ATC_DATA_SUB_VERSION;
	const char self_destruction = static_cast<char>(self_destruction_);
	const char token_string[] = "_AttacheCaseData";
	const int32_t data_file_version = ATC_DATA_FILE_VERSION;
	const int32_t algorism_type = ATC_ALGORISM_TYPE_RIJNDAEL;

	//データサブバージョン
	dst->write(&data_sub_version, sizeof(char));

	//予約データ(reserved)
	dst->write(null, sizeof(char));

	//ミスタイプ回数
	dst->write(&passwd_try_limit_, sizeof(char));

	//自己破壊
	dst->write(&self_destruction, sizeof(char));

	//トークン
	dst->write(token_string, 16);

	//データファイルバージョン
	dst->write(reinterpret_cast<const char*>(&data_file_version), sizeof(int32_t));

	//アルゴリズムタイプ
	dst->write(reinterpret_cast<const char*>(&algorism_type), sizeof(int32_t));

	rijndael_.MakeKey(key, CRijndael::sm_chain0, ATC_KEY_SIZE, ATC_BUF_SIZE);

	if (dst->good())
	{
		return ATC_OK;
	} else {
		return ATC_ERR_OSTREAM_FAILURE;
	}
}

ATCResult ATCLocker_impl::close()
{
	return ATCLocker_impl::finish();
}

ATCResult ATCLocker_impl::addFileEntry(const ATCFileEntry& entry)
{
	if (entry.name_sjis.size() > 0 && entry.name_utf8.size())
	{
		entries_.push_back(entry);
		return ATC_OK;
	} else {
		return ATC_ERR_INVARID_FILE_ENTRY;
	}
}

namespace {
	template <class T>
	string convertToString(T src)
	{
		stringstream converter;
		converter << src;
		return converter.str();
	}

	void unix_to_ttime(time_t unix, int32_t *dt, int32_t *tm)
	{
		// 西洋紀元からUNIX紀元までの日数
		int32_t const days_between_ad_epoch_and_unix_epoch = 719162;
		*dt = days_between_ad_epoch_and_unix_epoch + static_cast<int32_t>(unix) / (60 * 60 * 24) + 1;

		struct tm timeinfo;

#ifdef WIN32
			gmtime_s(&timeinfo, &unix);
#else
			timeinfo = *gmtime(&unix);
#endif

		*tm = timeinfo.tm_sec * 1000 + 
			timeinfo.tm_min   * 1000 * 60 + 
			timeinfo.tm_hour  * 1000 * 60 * 60;
	}
}

ATCResult ATCLocker_impl::writeEncryptedHeader(ostream *dst)
{
	string date_string;
	getCurrentDateString(&date_string);

	char separator[] = {(char)0xef, (char)0xbb, (char)0xbf};
	string sjis_header = "Passcode:AttacheCase\n\r\nLastDateTime:" + date_string + "\n\r\n";
	string utf8_header = "Passcode:AttacheCase\n\r\nLastDateTime:" + date_string + "\n\r\n";

	int32_t count = 0;
	for (vector<ATCFileEntry>::iterator it = entries_.begin(); it != entries_.end(); ++it)
	{
		sjis_header += "Fn_" + convertToString(count) + ":";
		utf8_header += "U_"  + convertToString(count) + ":";

		sjis_header += it->name_sjis + "\t";
		utf8_header += it->name_utf8 + "\t";

		string common;
		if (it->size < 0) {
			common += "*\t";
		} else {
			common += convertToString(it->size) + "\t";
			total_length_ += it->size;
		}

		common += convertToString(it->attribute)   + "\t";

		int32_t change_dt, change_tm;
		int32_t create_dt, create_tm;

		// UNIX時間 から TTimeStampへ変換
		unix_to_ttime(it->change_unix_time, &change_dt, &change_tm);
		unix_to_ttime(it->create_unix_time, &create_dt, &create_tm);

		common += convertToString(change_dt) + "\t";
		common += convertToString(change_tm) + "\t";
		common += convertToString(create_dt) + "\t";
		common += convertToString(create_tm);
		common += "\r\n";

		sjis_header += common;
		utf8_header += common;

		count++;
	}

	stringstream whole_header(sjis_header + string(separator, sizeof(separator)) + utf8_header);

	//暗号化部分のヘッダデータサイズを計算
	const int32_t block_length = (whole_header.str().size() + ATC_BUF_SIZE - 1) / ATC_BUF_SIZE;
	const int32_t encrypt_header_size = block_length * ATC_BUF_SIZE;

	dst->write(reinterpret_cast<const char*>(&encrypt_header_size), sizeof(int32_t));

	//初期化ベクトル（IV）を生成
	fillrand(chain_buffer_, ATC_BUF_SIZE);
	dst->write(chain_buffer_, ATC_BUF_SIZE);

	char buffer[ATC_BUF_SIZE] = {0};

	while (whole_header.read(buffer, ATC_BUF_SIZE).gcount() != 0)
	{
		encryptBuffer(buffer, chain_buffer_);

		dst->write(buffer, ATC_BUF_SIZE);
		for (int i = 0; i < ATC_BUF_SIZE; i++ ){
			buffer[i] = 0;
		}
	}

	//初期化ベクトル（IV）を生成
	fillrand(chain_buffer_, ATC_BUF_SIZE);
	dst->write(chain_buffer_, ATC_BUF_SIZE);

    z_.zalloc = Z_NULL;
    z_.zfree  = Z_NULL;
    z_.opaque = Z_NULL;

    if (deflateInit(&z_, compression_level_) != Z_OK)
	{
        return ATC_ERR_ZLIB_ERROR;
    }

    z_.avail_in = 0;
    z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
    z_.avail_out = ATC_BUF_SIZE;
    z_flush_ = Z_NO_FLUSH;

	return ATC_OK;
}

ATCResult ATCLocker_impl::writeFileData(ostream *dst, istream *src, size_t length)
{
	int rest_length = length;
    while (1)
	{
        if (z_.avail_in == 0)
		{
			size_t read_length = (rest_length < ATC_BUF_SIZE) ? rest_length : ATC_BUF_SIZE;

            z_.next_in = reinterpret_cast<Bytef*>(input_buffer_);
			z_.avail_in = static_cast<uInt>(src->read(input_buffer_, read_length).gcount());
			
			rest_length -= z_.avail_in;
			total_write_length_ += z_.avail_in;

			if (total_write_length_ >= total_length_) 
			{
				z_flush_ = Z_FINISH;
			}
        }

		// TODO: コメントアウトするとなぜか正常に出力しない
		// if(z_.avail_in == 0) break;

        z_status_ = deflate(&z_, z_flush_);

        if (z_status_ == Z_STREAM_END)
		{
			break;
		}

        if (z_status_ != Z_OK)
		{
			if (z_status_ == Z_BUF_ERROR)
			{
				return ATC_OK;
			} else {
				return ATC_ERR_ZLIB_ERROR;
			}
        }

        if (z_.avail_out == 0)
		{
			encryptBuffer(output_buffer_, chain_buffer_);
			dst->write(output_buffer_, ATC_BUF_SIZE);

			z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
			z_.avail_out = ATC_BUF_SIZE;
        }
    }

    if (z_status_ == Z_STREAM_END)
	{
		int32_t count;
		if ((count = ATC_BUF_SIZE - z_.avail_out) != 0)
		{
			char padding_num = (char)z_.avail_out;
			for(int i = count; i < ATC_BUF_SIZE; i++)
			{
				output_buffer_[i] = padding_num;
			}
			encryptBuffer(output_buffer_, chain_buffer_);
			dst->write(output_buffer_, ATC_BUF_SIZE);
		}

		return finish();
	}

	return ATC_OK;
}

ATCResult ATCLocker_impl::finish()
{
	if (!finished_)
	{
		finished_ = true;
		if (deflateEnd(&z_) != Z_OK)
		{
			return ATC_ERR_ZLIB_ERROR;
		}
	}

	return ATC_OK;
}

void ATCLocker_impl::fillrand(char *buf, const int len)
{
	static unsigned long count = 4;
	static char          r[4];
	int                  i;

	// ISAAC ( Cryptographic Random Number Generator )
	randctx ctx;

	// init
	randinit(&ctx, 1);

	for(i = 0; i < len; ++i){
		if(count == 4){
			*(unsigned long*)r = rand(&ctx);
			count = 0;
		}
		buf[i] = r[count++];
	}
}

void ATCLocker_impl::getCurrentDateString(string *dst)
{
	time_t rawtime;
	struct tm timeinfo;
	char buffer [80];

	time (&rawtime);

#ifdef WIN32
	localtime_s(&timeinfo, &rawtime);
#else
	timeinfo = *localtime(&rawtime);
#endif

	strftime(buffer, 80, "%Y/%m/%d %H:%M:%S", &timeinfo);

	*dst = string(buffer);
}


void ATCLocker_impl::encryptBuffer(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE])
{
	// xor
	for (int i = 0; i < ATC_BUF_SIZE; i++ ){
		data_buffer[i] ^= iv_buffer[i];
	}

	// rijndael
	rijndael_.EncryptBlock(data_buffer, data_buffer);

	//CBC
	for (int i = 0; i < ATC_BUF_SIZE; i++ ){
		iv_buffer[i] = data_buffer[i];
	}
}

char ATCLocker_impl::passwd_try_limit() const
{
	return passwd_try_limit_;
}

bool ATCLocker_impl::self_destruction() const
{
	return self_destruction_;
}

int32_t ATCLocker_impl::compression_level() const
{
	return compression_level_;
}

void ATCLocker_impl::set_passwd_try_limit(const char passwd_try_limit)
{
	passwd_try_limit_ = passwd_try_limit;
}

void ATCLocker_impl::set_self_destruction(const bool self_destruction)
{
	self_destruction_ = self_destruction;
}

void ATCLocker_impl::set_compression_level(const int32_t compression_level)
{
	compression_level_ = compression_level;
}
