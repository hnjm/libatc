#pragma once

#include <cstdint>

#include "ATCCommon.h"

using namespace std;

class ATCUnlocker_impl;

class ATCUnlocker
{
public:
	ATCUnlocker();
	~ATCUnlocker();

	ATCResult open(istream *src, const char key[ATC_KEY_SIZE]);
	ATCResult close();

	size_t getEntryLength() const;
	ATCResult getEntry(ATCFileEntry *entry, size_t index);
	ATCResult extractFileData(ostream *dst, istream *src, size_t length);

public:
	int32_t data_version() const;
	char data_sub_version() const;
	int32_t algorism_type() const;
	char passwd_try_limit() const;
	bool self_destruction() const;

private:
	ATCUnlocker_impl *impl_;

};