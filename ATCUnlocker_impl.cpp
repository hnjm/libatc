/*

Copyright (c) h2so5 <mail@h2so5.net>

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

   3. This notice may not be removed or altered from any source
   distribution.

*/

#include "ATCUnlocker_impl.h"


ATCUnlocker_impl::ATCUnlocker_impl() :

data_version_(ATC_DATA_FILE_VERSION),
data_sub_version_(ATC_DATA_SUB_VERSION),

algorism_type_(ATC_ALGORISM_TYPE_RIJNDAEL),

passwd_try_limit_(ATC_DEFAULT_PASSWORD_TRY_LIMIT),
self_destruction_(false),

total_length_(0),
total_read_length_(0)

{
}


ATCUnlocker_impl::~ATCUnlocker_impl()
{

}

ATCResult ATCUnlocker_impl::open(istream *src, const char key[ATC_KEY_SIZE])
{
	char token[16];
	static const char token_string[] = "_AttacheCaseData";
	static const char broken_token_string[] = "_Atc_Broken_Data";

	char plain_header_info[4] = {0, 0, 0, 0};
	int32_t encrypted_header_size = 0;

	src->seekg(0, ios::beg);
	src->read(plain_header_info, sizeof(plain_header_info));
	src->read(token, sizeof(token));

	if (memcmp(token, token_string, sizeof(token)) != 0)
	{
		if (memcmp(token, broken_token_string, sizeof(token)) == 0)
		{
			src->clear();
			return ATC_ERR_DESTRUCTED_FILE;
		}
		else
		{
			// 自己実行形式ファイルかどうかチェック

			src->seekg(0, ios::end);
			int64_t total = src->tellg();

			src->seekg(total - sizeof(int64_t), ios::beg);
			src->read(reinterpret_cast<char*>(&total_length_), sizeof(total_length_));

			int64_t header_pos = -(total_length_ + sizeof(int64_t));

			if (total + header_pos < 0)
			{
				src->clear();
				return ATC_ERR_UNENCRYPTED_FILE;
			}
        
			src->clear();
			src->seekg(static_cast<streamoff>(header_pos), ios::end);

			src->read(plain_header_info, sizeof(plain_header_info));
			src->read(token, sizeof(token));

			// トークンを再チェック
			if (memcmp(token, token_string, sizeof(token)) != 0)
			{
				src->clear();
				return ATC_ERR_UNENCRYPTED_FILE;
			}
		}
	}

	// キーが指定されていない場合は有効な暗号ファイルかどうかのチェックだけ行う
	if (!key)
	{
		src->clear();
		return ATC_OK;
	}

	src->read(reinterpret_cast<char*>(&data_version_), sizeof(data_version_));

	if (data_version_ > ATC_DATA_FILE_VERSION && data_version_ < 200)
	{
		src->clear();
		return ATC_ERR_UNSUPPORTED_VERSION;
	}
	else if (data_version_ <= 103)
	{
		const char *str_end = find(&key[0], &key[ATC_KEY_SIZE - 1], '\0');
		string key_str = string(&key[0], str_end) + PASS_FOOTER;

		blowfish_.SetKey(reinterpret_cast<const unsigned char*>(key_str.c_str()), key_str.size());

		encrypted_header_size = *reinterpret_cast<int32_t*>(plain_header_info);
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

		// IVの読み込み
		src->read(chain_buffer_, ATC_BUF_SIZE);

		// キーをセット
		rijndael_.MakeKey(key, CRijndael::sm_chain0, ATC_KEY_SIZE, ATC_BUF_SIZE);
	}
	
	stringstream pms;
	streamsize len = 0;
	while (len < encrypted_header_size)
	{
		char source_buffer[ATC_BUF_SIZE] = {0};
		len += src->read(source_buffer, ATC_BUF_SIZE).gcount();

		if (data_version_ <= 103)
		{
			decryptBufferBlowfish(source_buffer);
		} else {
			decryptBufferRijndael(source_buffer, chain_buffer_);
		}

		// 最初のブロックで復号に成功したかどうかチェック
		if (len == ATC_BUF_SIZE)
		{
			if (string(source_buffer, ATC_BUF_SIZE).find("Passcode") == string::npos)
			{
				src->clear();
				src->seekg(0, ios::beg);
				return ATC_ERR_WRONG_KEY;
			}
		}

		pms.write(source_buffer, ATC_BUF_SIZE);
	}

	// ヘッダのファイルエントリを解析
	if(!parseHeaderEntries(&pms))
	{
		return ATC_ERR_BROKEN_HEADER;
	}

	ifstream::pos_type cursor = src->tellg();
	src->seekg(0, ios::end);
	ifstream::pos_type file_length = src->tellg();
	src->seekg(cursor);

	// ファイル（データ本体）サイズを取得する
	total_length_ = file_length - cursor - ATC_BUF_SIZE;

	if (data_version_ > 103)
	{
		// IVの読み出し
		src->read(chain_buffer_, ATC_BUF_SIZE);
	}

	if (!initZlib())
	{
		return ATC_ERR_ZLIB_ERROR;
	}

	return ATC_OK;
}

ATCResult ATCUnlocker_impl::close()
{
	if (inflateEnd(&z_) != Z_OK)
	{
		return ATC_ERR_ZLIB_ERROR;
	} else {
		return ATC_OK;
	}
}

ATCResult ATCUnlocker_impl::getEntry(ATCFileEntry *entry, size_t index)
{
	if (index < entries_.size())
	{
		*entry = entries_.at(index);
		return ATC_OK;
	} else {
		return ATC_ERR_INVARID_INDEX;
	}
}

ATCResult ATCUnlocker_impl::extractFileData(ostream *dst, istream *src, size_t length)
{
	while (z_status_ != Z_STREAM_END)
	{
		if (z_.avail_in == 0)
		{
			z_.next_in = reinterpret_cast<Bytef*>(input_buffer_);
			
			const streamsize read_length = src->read(input_buffer_, ATC_BUF_SIZE).gcount();
			total_read_length_ += read_length;

			if (data_version_ <= 103)
			{
				decryptBufferBlowfish(input_buffer_);
			} else {
				decryptBufferRijndael(input_buffer_, chain_buffer_);
			}

			z_.avail_in = static_cast<uInt>(read_length);

			// 最終ブロック
			if (total_read_length_ >= total_length_)
			{
				char padding_num = input_buffer_[ATC_BUF_SIZE - 1];

				if (padding_num > -1)
				{
					size_t i = 0;
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
			if (z_status_ == Z_BUF_ERROR)
			{
				z_.avail_out = 0;
			} else 
			if (data_version_ <= 103 && z_status_ == Z_DATA_ERROR)
			{
				z_.avail_out = 0;
			} else {
				return ATC_ERR_ZLIB_ERROR;
			}
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

	const size_t tmp_buffer_size = tmp_buffer_.size();
	const size_t out_length = (tmp_buffer_size >= length) ? length : tmp_buffer_size;

	dst->write(tmp_buffer_.data(), out_length);
	tmp_buffer_.erase(0, out_length);

	return ATC_OK;
}

void ATCUnlocker_impl::decryptBufferRijndael(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE])
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
	}

	memcpy(iv_buffer, temp_buffer, ATC_BUF_SIZE);
}

void ATCUnlocker_impl::decryptBufferBlowfish(char data_buffer[ATC_BUF_SIZE])
{
	char temp_buffer[ATC_BUF_SIZE] = {0};
	memcpy(temp_buffer, data_buffer, ATC_BUF_SIZE);

	blowfish_.Decrypt(reinterpret_cast<unsigned char*>(data_buffer),
		reinterpret_cast<const unsigned char*>(data_buffer), ATC_BUF_SIZE);
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
		static const int32_t days_between_ad_epoch_and_unix_epoch = 719162;

		const int32_t seconds_from_midnight = tm / 1000;
		const int32_t days_from_epoch = dt - days_between_ad_epoch_and_unix_epoch - 1;

		return days_from_epoch * 60 * 60 * 24 + seconds_from_midnight;
	}
}

bool ATCUnlocker_impl::parseFileEntry(ATCFileEntry *entry, const std::string& tsv_sjis, const std::string& tsv_utf8)
{
	const size_t start_pos = tsv_sjis.find(':') + 1;
	size_t tab_pos = tsv_sjis.find('\t', start_pos);
	entry->name_sjis = tsv_sjis.substr(start_pos, tab_pos - start_pos);

	if (tsv_utf8.size() > 0)
	{
		const size_t start_pos_utf8 = tsv_utf8.find(':') + 1;
		const size_t tab_pos_utf8 = tsv_utf8.find('\t', start_pos_utf8);
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
	
	convertFromString(&entry->size,			number_strings[0], static_cast<int64_t>(-1));
	convertFromString(&entry->attribute,	number_strings[1], static_cast<int32_t>(-1));

	int32_t change_dt, change_tm;
	int32_t create_dt, create_tm;

	switch (number_strings.size())
	{
	case 6:
		convertFromString(&change_dt, number_strings[2], static_cast<int32_t>(-1));
		convertFromString(&change_tm, number_strings[3], static_cast<int32_t>(-1));
		convertFromString(&create_dt, number_strings[4], static_cast<int32_t>(-1));
		convertFromString(&create_tm, number_strings[5], static_cast<int32_t>(-1));
		break;
	case 3:
		convertFromString(&change_dt, number_strings[2], static_cast<int32_t>(-1));
		convertFromString(&change_tm, number_strings[2], static_cast<int32_t>(-1));
		convertFromString(&create_dt, number_strings[2], static_cast<int32_t>(-1));
		convertFromString(&create_tm, number_strings[2], static_cast<int32_t>(-1));
		break;
	default:
		return false;
	}

	// TTimeStamp から UNIX時間へ変換
	entry->change_unix_time = ttime_to_unix(change_dt, change_tm);
	entry->create_unix_time = ttime_to_unix(create_dt, create_tm);

	return true;
}

bool ATCUnlocker_impl::initZlib()
{
	// zlib準備
	z_.zalloc = Z_NULL;
	z_.zfree = Z_NULL;
	z_.opaque = Z_NULL;

	if (inflateInit(&z_) != Z_OK)
	{
		return false;
	}

	// 通常は deflate() の第2引数は Z_NO_FLUSH にして呼び出す
	z_flush_ = Z_NO_FLUSH;

	z_.avail_in  = 0;
	z_.next_in   = Z_NULL;
	z_.next_out  = reinterpret_cast<Bytef*>(output_buffer_);
	z_.avail_out = ATC_LARGE_BUF_SIZE;
	z_status_    = Z_OK;

	return true;
}

bool ATCUnlocker_impl::parseHeaderEntries(stringstream *pms)
{
	pms->seekg(0, ios::beg);

	vector<string> DataList;
	while (!pms->eof())
	{
		char line_buffer[ATC_LINE_BUF_SIZE] = {0};
		pms->getline(line_buffer, ATC_LINE_BUF_SIZE);

		if (strcmp(line_buffer, "\r") != 0)
		{
			DataList.push_back(line_buffer);
		}
	}

	if (DataList.size() == 0)
	{
		return false;
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

	const size_t item_size = sjis_list.size();
	const bool utf8_available = (utf8_list.size() == item_size);
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
			return false;
		}
	}

	return true;
}

size_t ATCUnlocker_impl::getEntryLength() const
{
	return entries_.size();
}

int32_t ATCUnlocker_impl::data_version() const
{
	return data_version_;
}

char ATCUnlocker_impl::data_sub_version() const
{
	return data_sub_version_;
}

int32_t ATCUnlocker_impl::algorism_type() const
{
	return algorism_type_;
}

char ATCUnlocker_impl::passwd_try_limit() const
{
	return passwd_try_limit_;
}

bool ATCUnlocker_impl::self_destruction() const
{
	return self_destruction_;
}


#ifdef USE_CLI

namespace {

void readToBuffer(char* dst, Stream ^src, size_t length)
{
	array<System::Byte, 1>^ buffer = gcnew array<System::Byte, 1>(length);
	src->Read(buffer, 0, buffer->Length);

	pin_ptr<System::Byte> buffer_native = &buffer[0];
	memcpy(dst, buffer_native, buffer->Length);

	buffer = nullptr;
}

};

ATCResult ATCUnlocker_impl::open(Stream ^src, array<System::Byte, 1> ^key)
{
	array<System::Byte, 1>^ key_buffer = gcnew array<System::Byte, 1>(ATC_KEY_SIZE);

	if (key)
	{
		key->CopyTo(key_buffer, 0);
	}

	array<System::Byte, 1>^ token = gcnew array<System::Byte, 1>(32);
	static const char token_string[] = "_AttacheCaseData";
	static const char broken_token_string[] = "_Atc_Broken_Data";

	array<System::Byte, 1>^ plain_header_info = gcnew array<System::Byte, 1>(4);
	int32_t encrypted_header_size = 0;

	src->Seek(0, SeekOrigin::Begin);
	src->Read(plain_header_info, 0, plain_header_info->Length);
	src->Read(token, 0, 16);

	// トークンのバイト列を固定
	pin_ptr<System::Byte> token_native = &token[0];

	if (memcmp(token_native, token_string, 16) != 0)
	{
		if (memcmp(token_native, broken_token_string, 16) == 0)
		{
			src->Seek(0, SeekOrigin::Begin);
			return ATC_ERR_DESTRUCTED_FILE;
		}
		else
		{
			// 自己実行形式ファイルかどうかチェック

			src->Seek(0, SeekOrigin::End);
			int64_t total = src->Position;

			src->Seek(total - sizeof(int64_t), SeekOrigin::Begin);

			readToBuffer(reinterpret_cast<char*>(&total_length_), src, sizeof(total_length_));

			int64_t header_pos = -(total_length_ + sizeof(int64_t));

			if (total + header_pos < 0)
			{
				src->Seek(0, SeekOrigin::Begin);
				return ATC_ERR_UNENCRYPTED_FILE;
			}
        
			src->Seek(total - sizeof(int64_t), SeekOrigin::Begin);

			readToBuffer(reinterpret_cast<char*>(&total_length_), src, sizeof(total_length_));
        
			src->Seek(-(total_length_ + sizeof(int64_t)), SeekOrigin::End);

			src->Read(plain_header_info, 0, plain_header_info->Length);
			src->Read(token, 0, 16);

			// トークンを再チェック
			if (memcmp(token_native, token_string, 16) != 0)
			{
				src->Seek(0, SeekOrigin::Begin);
				return ATC_ERR_UNENCRYPTED_FILE;
			}
		}
	}

	// トークンのバイト列を解放
	token_native = nullptr;

	if (!key)
	{
		src->Seek(0, SeekOrigin::Begin);
		return ATC_OK;
	}

	// データバージョンを読み込み
	readToBuffer(reinterpret_cast<char*>(&data_version_), src, sizeof(data_version_));

	if (data_version_ > ATC_DATA_FILE_VERSION && data_version_ < 200)
	{
		src->Seek(0, SeekOrigin::Begin);
		return ATC_ERR_UNSUPPORTED_VERSION;
	}
	else if (data_version_ <= 103)
	{
		pin_ptr<System::Byte> key_native = &key_buffer[0];
		const char *str_end = find(reinterpret_cast<char*>(&key_native[0]),
			reinterpret_cast<char*>(&key_native[ATC_KEY_SIZE - 1]), '\0');

		string key_str = string(reinterpret_cast<char*>(&key_native[0]), str_end) + PASS_FOOTER;
		key_native = nullptr;

		blowfish_.SetKey(reinterpret_cast<const unsigned char*>(key_str.data()), key_str.size());
		
		pin_ptr<System::Byte> plain_header_info_native = &plain_header_info[0];
		encrypted_header_size = *reinterpret_cast<int32_t*>(plain_header_info_native);
		plain_header_info_native = nullptr;
	}
	else
	{
		// 104 ～
		// Rijndaelで暗号化されている
		readToBuffer(reinterpret_cast<char*>(&algorism_type_), src, sizeof(algorism_type_));
		readToBuffer(reinterpret_cast<char*>(&encrypted_header_size), src, sizeof(encrypted_header_size));

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

		// IVの読み込み
		readToBuffer(reinterpret_cast<char*>(&chain_buffer_), src, ATC_BUF_SIZE);

		// キーをセット
		{
			pin_ptr<System::Byte> buffer_native = &key_buffer[0];
			rijndael_.MakeKey(reinterpret_cast<const char*>(buffer_native),
				CRijndael::sm_chain0, ATC_KEY_SIZE, ATC_BUF_SIZE);

			buffer_native = nullptr;
		}
	}

	stringstream pms;
	streamsize len = 0;
	while (len < encrypted_header_size)
	{
		array<System::Byte, 1>^ buffer = gcnew array<System::Byte, 1>(ATC_BUF_SIZE);
		len += src->Read(buffer, 0, buffer->Length);

		pin_ptr<System::Byte> source_buffer = &buffer[0];
		
		if (data_version_ <= 103)
		{
			decryptBufferBlowfish(reinterpret_cast<char*>(source_buffer));
		} else {
			decryptBufferRijndael(reinterpret_cast<char*>(source_buffer), chain_buffer_);
		}

		// 最初のブロックで復号に成功したかどうかチェック
		if (len == ATC_BUF_SIZE)
		{
			if (string(reinterpret_cast<const char*>(source_buffer),
				ATC_BUF_SIZE).find("Passcode") == string::npos)
			{
				src->Seek(0, SeekOrigin::Begin);
				return ATC_ERR_WRONG_KEY;
			}
		}

		pms.write(reinterpret_cast<const char*>(source_buffer), ATC_BUF_SIZE);
		source_buffer = nullptr;
	}

	// ヘッダのファイルエントリを解析
	if(!parseHeaderEntries(&pms))
	{
		return ATC_ERR_BROKEN_HEADER;
	}

	ifstream::pos_type cursor = src->Position;
	src->Seek(0, SeekOrigin::End);
	ifstream::pos_type file_length = src->Position;
	src->Seek(cursor, SeekOrigin::Begin);

	// ファイル（データ本体）サイズを取得する
	total_length_ = file_length - cursor - ATC_BUF_SIZE;

	if (data_version_ > 103)
	{
		// IVの読み出し
		readToBuffer(reinterpret_cast<char*>(&chain_buffer_), src, ATC_BUF_SIZE);
	}

	if (!initZlib())
	{
		return ATC_ERR_ZLIB_ERROR;
	}

	return ATC_OK;
}

ATCResult ATCUnlocker_impl::extractFileData(Stream ^dst, Stream ^src, size_t length)
{
	while (z_status_ != Z_STREAM_END)
	{
		if (z_.avail_in == 0)
		{
			z_.next_in = reinterpret_cast<Bytef*>(input_buffer_);
			
			array<System::Byte, 1>^ buffer = gcnew array<System::Byte, 1>(ATC_BUF_SIZE);
			const streamsize read_length = src->Read(buffer, 0, buffer->Length);

			{
				pin_ptr<System::Byte> buffer_native = &buffer[0];
				memcpy(input_buffer_, buffer_native, ATC_BUF_SIZE);

				buffer_native = nullptr;
			}

			total_read_length_ += read_length;


			if (data_version_ <= 103)
			{
				decryptBufferBlowfish(input_buffer_);
			} else {
				decryptBufferRijndael(input_buffer_, chain_buffer_);
			}

			z_.avail_in = static_cast<uInt>(read_length);

			// 最終ブロック
			if (total_read_length_ >= total_length_)
			{
				char padding_num = input_buffer_[ATC_BUF_SIZE - 1];

				if (padding_num > -1)
				{
					size_t i = 0;
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
			if (z_status_ == Z_BUF_ERROR)
			{
				z_.avail_out = 0;
			} else 
			if (data_version_ <= 103 && z_status_ == Z_DATA_ERROR)
			{
				z_.avail_out = 0;
			} else {
				return ATC_ERR_ZLIB_ERROR;
			}
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

	const size_t tmp_buffer_size = tmp_buffer_.size();
	const size_t out_length = (tmp_buffer_size >= length) ? length : tmp_buffer_size;

	{
		array<System::Byte, 1>^ buffer = gcnew array<System::Byte, 1>(out_length);
		pin_ptr<System::Byte> buffer_native = &buffer[0];

		memcpy(buffer_native, tmp_buffer_.data(), out_length);

		dst->Write(buffer, 0, out_length);
		buffer_native = nullptr;
	}
	
	tmp_buffer_.erase(0, out_length);

	return ATC_OK;
}

#endif