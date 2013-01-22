#pragma once

#include <string>
#include <cstdint>

#include "ATCCommon.h"

using namespace std;

enum {

	ATC_DATA_FILE_VERSION			= 105,
	ATC_DATA_SUB_VERSION			= 6,
	
	ATC_KEY_SIZE					= 32,
	ATC_BUF_SIZE					= 32,
	ATC_LARGE_BUF_SIZE				= 1024,
	ATC_LINE_BUF_SIZE				= 2048,

	ATC_DEFAULT_PASSWORD_TRY_LIMIT	= 3,
	ATC_MIN_PASSWORD_TRY_LIMIT		= 1,
	ATC_MAX_PASSWORD_TRY_LIMIT		= 10,

	ATC_ALGORISM_TYPE_BLOWFISH		= 0,  // Blowfish
	ATC_ALGORISM_TYPE_RIJNDAEL		= 1   // Rijndael

};

enum ATCResult{

	ATC_OK,
	ATC_FINISHED,
	ATC_CURRENT_FILE_FINISHED,

	ATC_ERR_WRONG_KEY,
	ATC_ERR_NULL_KEY,
	ATC_ERR_INVARID_FILE_ENTRY,
	ATC_ERR_BROKEN_HEADER,
	ATC_ERR_UNSUPPORTED_VERSION,
	ATC_ERR_OSTREAM_FAILURE,
	ATC_ERR_NO_PLAIN_HEADER,
	ATC_ERR_INVARID_INDEX,

	ATC_ERR_ZLIB_ERROR

};

struct ATCFileEntry{

	string  name_sjis;
	string  name_utf8;

	int64_t size;
	int32_t attribute;

	time_t change_unix_time;
	time_t create_unix_time;

};