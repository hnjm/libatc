/*

Copyright (c) 2013 h2so5 <mail@h2so5.net>

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

#pragma once

#include "../../ATCUnlocker.h"
#include "../../ATCLocker.h"

#using<system.dll>

using namespace System;

namespace AttacheCase {

public enum class Result
{

	OK,
	FINISHED,
	CURRENT_FILE_FINISHED,

	ERR_WRONG_KEY,
	ERR_NULL_KEY,
	ERR_INVARID_FILE_ENTRY,
	ERR_BROKEN_HEADER,
	ERR_UNSUPPORTED_VERSION,
	ERR_OSTREAM_FAILURE,
	ERR_NO_PLAIN_HEADER,
	ERR_INVARID_INDEX,

	ERR_ZLIB_ERROR

};

public ref class FileEntry
{
public:
	FileEntry() :
		NameSJIS(gcnew System::String("")),
		NameUTF8(gcnew System::String(""))
	{
	}

	System::String ^NameSJIS;
	System::String ^NameUTF8;

	int64_t Size;
	int32_t Attribute;

	System::DateTime ChangeDateTime;
	System::DateTime CreateDateTime;

};

public ref class Unlocker
{
public:
	Unlocker();
	~Unlocker();

public:
	Result Open(Stream ^src, array<System::Byte, 1> ^key);
	Result Close();

	Result GetEntry(FileEntry ^entry, size_t index);
	Result ExtractFileData(Stream ^dst, Stream ^src, size_t length);

public:
	property size_t EntryLength { size_t get(); }
	property int32_t DataVersion { int32_t get(); }
	property char DataSubVersion { char get(); }
	property int32_t AlgorismType { int32_t get(); }
	property char PasswdTryLimit { char get(); }
	property bool SelfDestruction { bool get(); }

private:
	ATCUnlocker_impl *impl_;

};

public ref class Locker
{
public:
	Locker();
	~Locker();

	Result Open(Stream ^dst, array<System::Byte, 1> ^key);
	Result Close();

	Result AddFileEntry(FileEntry ^entry);
	Result WriteEncryptedHeader(Stream ^dst);
	Result WriteFileData(Stream ^dst, Stream ^src, size_t length);

public:
	property char PasswdTryLimit
	{
		char get();
		void set(char passwd_try_limit);
	}

	property bool SelfDestruction
	{
		bool get();
		void set(bool self_destruction);
	}

	property int32_t CompressionLevel
	{
		int32_t get();
		void set(int32_t compression_level);
	}

	property DateTime^ CreateTime
	{
		DateTime^ get();
		void set(DateTime^ create_time);
	}

private:
	ATCLocker_impl *impl_;

};

}
