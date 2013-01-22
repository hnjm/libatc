#pragma once

#include <cstdint>
#include "ATCCommon.h"

using namespace std;

class ATCLocker_impl;

class ATCLocker
{
public:
	ATCLocker();
	~ATCLocker();

	ATCResult open(ostream *dst, const char key[ATC_KEY_SIZE]);
	ATCResult close();

	ATCResult addFileEntry(const ATCFileEntry& entry);
	ATCResult writeEncryptedHeader(ostream *dst);
	ATCResult writeFileData(ostream *dst, istream *src, size_t length);

public:
	char passwd_try_limit()	const;
	bool self_destruction()	const;
	int32_t compression_level() const;
	time_t create_time() const;

	void set_passwd_try_limit(char passwd_try_limit);
	void set_self_destruction(bool self_destruction);
	void set_compression_level(int32_t compression_level);
	void set_create_time(time_t create_time);

private:
	ATCLocker_impl *impl_;

};