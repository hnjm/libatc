#include <cassert>

#include "ATCUnlocker.h"
#include "rijndael.h"

ATCUnlocker::ATCUnlocker() :

data_version_(ATC_DATA_FILE_VERSION),
data_sub_version_(ATC_DATA_SUB_VERSION),

algorism_type_(ATC_ALGORISM_TYPE_RIJNDAEL),

passwd_try_limit_(ATC_DEFAULT_PASSWORD_TRY_LIMIT),
self_destruction_(false),

total_length_(0),
total_read_length_(0)

{
}


ATCUnlocker::~ATCUnlocker()
{
	close();
}

ATCResult ATCUnlocker::open(istream *src, const char key[ATC_KEY_SIZE])
{
	const char zero[ATC_BUF_SIZE] = {0};
	if (memcmp(zero, key, ATC_BUF_SIZE) == 0)
	{
		return ATC_ERR_NULL_KEY;
	}

	char token[16];
	const char charTokenString[] = "_AttacheCaseData";

	char plain_header_info[4] = {0};
	int32_t encrypted_header_size = 0;

	src->read(plain_header_info, sizeof(plain_header_info));
	src->read(token, sizeof(token));

	// トークンを検証
	if (memcmp(token, charTokenString, sizeof(token)) != 0)
	{
		// 自己実行形式ファイルかどうかチェック

		src->seekg(0, ios::end);
		int64_t total = src->tellg();

		src->seekg(total - sizeof(int64_t), ios::beg);
		src->read(reinterpret_cast<char*>(&total_length_), sizeof(total_length_));
		src->seekg(static_cast<streamoff>(-(total_length_ + sizeof(total_length_))), ios::end);

		src->read(plain_header_info, sizeof(plain_header_info));
		src->read(token, sizeof(token));

		// トークンを再チェック
		if (memcmp(token, charTokenString, sizeof(token)) != 0)
		{
			return ATC_ERR_BROKEN_HEADER;
		}
	}

	src->read(reinterpret_cast<char*>(&data_version_), sizeof(data_version_));

	if (data_version_ > ATC_DATA_FILE_VERSION && data_version_ < 200)
	{
		return ATC_ERR_UNSUPPORTED_VERSION;
	}
	else if (data_version_ <= 103)
	{
		return ATC_ERR_UNSUPPORTED_VERSION;
	}
	else
	{
		// 104 ～
		// Rijndaelで暗号化されている

		src->read(reinterpret_cast<char*>(&algorism_type_), sizeof(algorism_type_));
		src->read(reinterpret_cast<char*>(&encrypted_header_size), sizeof(encrypted_header_size));

		// データサブバージョンチェック（ver.2.70～）
		if (plain_header_info[0] >= 6)
		{
			passwd_try_limit_ = plain_header_info[2];
			self_destruction_ = (plain_header_info[3] == 0) ? false : true;

			// 有効範囲（1～10）かチェック
			if (passwd_try_limit_ < ATC_MIN_PASSWORD_TRY_LIMIT ||
					passwd_try_limit_ > ATC_MAX_PASSWORD_TRY_LIMIT)
			{
				passwd_try_limit_ = ATC_DEFAULT_PASSWORD_TRY_LIMIT;
			}
		}
		else
		{
			passwd_try_limit_ = ATC_DEFAULT_PASSWORD_TRY_LIMIT;
			self_destruction_ = false;
		}
	}

	// IVの読み込み
	src->read(chain_buffer_, ATC_BUF_SIZE);

	// キーをセット
	rijndael_.MakeKey(key, CRijndael::sm_chain0, ATC_KEY_SIZE, ATC_BUF_SIZE);
	
	stringstream pms;
	streamsize len = 0;
	while (len < encrypted_header_size)
	{
		char source_buffer[ATC_BUF_SIZE] = {0};
		len += src->read(source_buffer, ATC_BUF_SIZE).gcount();

		decryptBuffer(source_buffer, chain_buffer_);

		pms.write(source_buffer, ATC_BUF_SIZE);
	}

	pms.seekg(ios::beg);

	vector<string> DataList;
	while (!pms.eof())
	{
		char line_buffer[ATC_LINE_BUF_SIZE] = {0};
		pms.getline(line_buffer, ATC_LINE_BUF_SIZE);

		if (strcmp(line_buffer, "\r") != 0)
		{
			DataList.push_back(line_buffer);
		}
	}

	// 復号に成功したかどうかチェック
	bool correct_passwd = !(DataList.size() == 0 || DataList[0].find("AttacheCase") == string::npos);
	if (!correct_passwd)
	{
		return ATC_ERR_WRONG_KEY;
	}

	create_date_string_ = DataList[1];

	vector<string> sjis_list;
	vector<string> utf8_list;

	for (vector<string>::iterator it = DataList.begin(); it != DataList.end(); ++it)
	{
		if (it->find("Fn_") == 0)
		{
			sjis_list.push_back(*it);
		}
		else if (it->find("U_") == 0)
		{
			utf8_list.push_back(*it);
		}
	}

	size_t item_size = sjis_list.size();
	bool utf8_available = (utf8_list.size() == item_size);
	for (size_t i = 0; i < item_size; ++i)
	{
		bool succeeded = false;
		ATCFileEntry entry;

		if (utf8_available) {
			succeeded = parseFileEntry(&entry, sjis_list[i], utf8_list[i]);
		} else {
			succeeded = parseFileEntry(&entry, sjis_list[i]);
		}

		if (succeeded) {
			entries_.push_back(entry);
		} else {
			return ATC_ERR_BROKEN_HEADER;
		}
	}

	ifstream::pos_type cursor = src->tellg();
	src->seekg(0, ios::end);
	ifstream::pos_type file_length = src->tellg();
	src->seekg(cursor);

	// ファイル（データ本体）サイズを取得する
	total_length_ = file_length - cursor;

	// IVの読み出し
	src->read(chain_buffer_, ATC_BUF_SIZE);

	// zlib準備
	z_.zalloc = Z_NULL;
	z_.zfree = Z_NULL;
	z_.opaque = Z_NULL;

	if (inflateInit(&z_) != Z_OK)
	{
		return ATC_ERR_ZLIB_ERROR;
	}

	// 通常は deflate() の第2引数は Z_NO_FLUSH にして呼び出す
	z_flush_ = Z_NO_FLUSH;

	z_.avail_in  = 0;
	z_.next_in   = Z_NULL;
	z_.next_out  = reinterpret_cast<Bytef*>(output_buffer_);
	z_.avail_out = ATC_LARGE_BUF_SIZE;
	z_status_    = Z_OK;

	return ATC_OK;
}

ATCResult ATCUnlocker::close()
{
	if (inflateEnd(&z_) != Z_OK)
	{
		return ATC_ERR_ZLIB_ERROR;
	} else {
		return ATC_OK;
	}
}

ATCResult ATCUnlocker::getEntry(ATCFileEntry *entry, size_t index)
{
	if (index < entries_.size())
	{
		*entry = entries_.at(index);
		return ATC_OK;
	} else {
		return ATC_ERR_INVARID_INDEX;
	}
}

ATCResult ATCUnlocker::extractFileData(ostream *dst, istream *src, size_t length)
{
	while (z_status_ != Z_STREAM_END)
	{
		if (z_.avail_in == 0)
		{
			z_.next_in = reinterpret_cast<Bytef*>(input_buffer_);

			streamsize read_length = src->read(input_buffer_, ATC_BUF_SIZE).gcount();
			total_read_length_ += read_length;

			decryptBuffer(input_buffer_, chain_buffer_);

			z_.avail_in = static_cast<uInt>(read_length);

			// 最終ブロック
			if (total_read_length_ >= total_length_)
			{
				char padding_num = input_buffer_[ATC_BUF_SIZE - 1];

				if (padding_num > -1)
				{
					size_t i;
					for (i = 0; i < ATC_BUF_SIZE; ++i)
					{
						if (input_buffer_[ATC_BUF_SIZE - 1 - i] !=  padding_num)
						{
							break;
						}
					}

					if (padding_num == i)
					{
						z_.avail_in = ATC_BUF_SIZE - i;
					}
				}
			}
		}

		z_status_ = inflate(&z_, Z_NO_FLUSH);

		if (z_status_ == Z_STREAM_END)
		{
			break;
		}

		if (z_status_ != Z_OK)
		{
			return ATC_ERR_ZLIB_ERROR;
		}

		if (z_.avail_out == 0)
		{
			tmp_buffer_ += string(output_buffer_, ATC_LARGE_BUF_SIZE);

			z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
			z_.avail_out = ATC_LARGE_BUF_SIZE;

			// 要求サイズを超えていた場合
			if (tmp_buffer_.size() >= length)
			{
				break;
			}
		}
	}

	if (z_status_ == Z_STREAM_END)
	{
		/* 残りを吐き出す */
		size_t count = 0;
		if ((count = ATC_LARGE_BUF_SIZE - z_.avail_out) != 0)
		{
			tmp_buffer_ += string(output_buffer_, count);
		}
	}


	size_t tmp_buffer_size = tmp_buffer_.size();
	size_t out_length = (tmp_buffer_size >= length) ? length : tmp_buffer_size;

	dst->write(tmp_buffer_.data(), out_length);
	tmp_buffer_.erase(0, out_length);

	return ATC_OK;
}

void ATCUnlocker::decryptBuffer(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE])
{
	char temp_buffer[ATC_BUF_SIZE] = {0};

	// あとのxorのためによけておく
	memcpy(temp_buffer, data_buffer, ATC_BUF_SIZE);

	// 復号処理
	rijndael_.DecryptBlock(data_buffer, data_buffer);

	// xor
	for (int c = 0; c < ATC_BUF_SIZE; c++)
	{
		data_buffer[c] ^= iv_buffer[c];
		iv_buffer[c] = temp_buffer[c];
	}
}

namespace {
	template <class T>
	void convertFromString(T *dst, const std::string& src, T def)
	{
		stringstream converter(src);
		if (!(converter >> *dst))
		{
			*dst = def;
		}
	}

	time_t ttime_to_unix(int32_t dt, int32_t tm)
	{
		// 西洋紀元からUNIX紀元までの日数
		int32_t const days_between_ad_epoch_and_unix_epoch = 719162;

		int32_t seconds_from_midnight = tm / 1000;
		int32_t days_from_epoch = dt - days_between_ad_epoch_and_unix_epoch - 1;

		return days_from_epoch * 60 * 60 * 24 + seconds_from_midnight;
	}
}

bool ATCUnlocker::parseFileEntry(ATCFileEntry *entry, const std::string& tsv_sjis, const std::string& tsv_utf8)
{
	size_t start_pos = tsv_sjis.find(':') + 1;
	size_t tab_pos = tsv_sjis.find('\t', start_pos);
	entry->name_sjis = tsv_sjis.substr(start_pos, tab_pos - start_pos);

	if (tsv_utf8.size() > 0)
	{
		size_t start_pos_utf8 = tsv_utf8.find(':') + 1;
		size_t tab_pos_utf8 = tsv_utf8.find('\t', start_pos_utf8);
		entry->name_utf8 = tsv_utf8.substr(start_pos_utf8, tab_pos_utf8 - start_pos_utf8);
	}

	vector<string> number_strings;
	number_strings.reserve(6);

	size_t next_tab_pos;

	while((next_tab_pos = tsv_sjis.find('\t', tab_pos + 1)) != string::npos)
	{
		string str = tsv_sjis.substr(tab_pos + 1, next_tab_pos - (tab_pos + 1));
		number_strings.push_back(str);
		tab_pos = next_tab_pos;
	}

	number_strings.push_back(tsv_sjis.substr(tab_pos + 1));

	if (number_strings.size() != 6)
	{
		return false;
	}

	convertFromString(&entry->size,			number_strings[0], static_cast<int64_t>(-1));
	convertFromString(&entry->attribute,	number_strings[1], static_cast<int32_t>(-1));

	int32_t change_dt, change_tm;
	int32_t create_dt, create_tm;
	convertFromString(&change_dt, number_strings[2], static_cast<int32_t>(-1));
	convertFromString(&change_tm, number_strings[3], static_cast<int32_t>(-1));
	convertFromString(&create_dt, number_strings[4], static_cast<int32_t>(-1));
	convertFromString(&create_tm, number_strings[5], static_cast<int32_t>(-1));

	// TTimeStamp から UNIX時間へ変換
	entry->change_unix_time = ttime_to_unix(change_dt, change_tm);
	entry->create_unix_time = ttime_to_unix(create_dt, create_tm);

	return true;
}

size_t ATCUnlocker::getEntryLength() const
{
	return entries_.size();
}

int32_t ATCUnlocker::data_version() const
{
	return data_version_;
}

char ATCUnlocker::data_sub_version() const
{
	return data_sub_version_;
}

char ATCUnlocker::passwd_try_limit() const
{
	return passwd_try_limit_;
}

bool ATCUnlocker::self_destruction() const
{
	return self_destruction_;
}