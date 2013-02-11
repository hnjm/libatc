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

#include "../../ATCUnlocker.h"
#include "../../ATCUnlocker_impl.h"
#include "../../ATCLocker.h"
#include "../../ATCLocker_impl.h"

#include "libatc_cli.h"

namespace {
	time_t dateTimeToUNIX(DateTime^ datetime)
	{
		DateTime^ tmp = DateTime(datetime);
		DateTime^ epoch = (gcnew DateTime(1970,1,1,0,0,0,0))->ToLocalTime();

		time_t a = (datetime->Ticks - epoch->Ticks) / 10000000;
		return a;
	}

	DateTime^ UNIXToDateTime(time_t unix_time)
	{
		return (gcnew DateTime(1970,1,1,0,0,0,0))->AddSeconds(static_cast<double>(unix_time)).ToLocalTime();
	}
}

namespace AttacheCase {

Unlocker::Unlocker() :

impl_(NULL)

{
	impl_ = new ATCUnlocker_impl();
}

Unlocker::~Unlocker()
{
	delete impl_;
	impl_ = NULL;
}

Result Unlocker::Open(Stream ^src, array<System::Byte, 1> ^key)
{
	return static_cast<Result>(impl_->open(src, key));
}

Result Unlocker::Open(Stream ^src, String ^key)
{
	return Unlocker::Open(src, Encoding::UTF8->GetBytes(key));
}

Result Unlocker::Open(Stream ^src)
{
	array<System::Byte, 1>^ tmp;
	return Unlocker::Open(src, tmp);
}

Result Unlocker::Close()
{
	return static_cast<Result>(impl_->close());
}

Result Unlocker::ExtractFileData(Stream ^dst, Stream ^src, int64_t length)
{
	return static_cast<Result>(impl_->extractFileData(dst, src, length));
}

int32_t Unlocker::DataVersion::get()
{
	return impl_->data_version();
}

char Unlocker::DataSubVersion::get()
{
	return impl_->data_sub_version();
}

int32_t Unlocker::AlgorismType::get()
{
	return impl_->algorism_type();
}

char Unlocker::PasswdTryLimit::get()
{
	return impl_->passwd_try_limit();
}

bool Unlocker::SelfDestruction::get()
{
	return impl_->self_destruction();
}

array<FileEntry^, 1>^ Unlocker::Entries::get()
{
	if (!entries_)
	{
		size_t length = impl_->getEntryLength();
		entries_ = gcnew array<FileEntry^, 1>(length);

		for (size_t i = 0; i < length; ++i)
		{
			FileEntry ^entry = gcnew FileEntry();
			ATCFileEntry entry_native;

			Result result = static_cast<Result>(impl_->getEntry(&entry_native, i));

			entry->NameSJIS = gcnew String(entry_native.name_sjis.c_str());
			entry->NameUTF8 = gcnew String(entry_native.name_utf8.c_str());

			entry->Size = entry_native.size;
			entry->Attribute = entry_native.attribute;

			entry->ChangeDateTime = *UNIXToDateTime(entry_native.change_unix_time);
			entry->CreateDateTime = *UNIXToDateTime(entry_native.create_unix_time);

			entries_[i] = entry;
		}
	}

	return entries_;
}


Locker::Locker() :

impl_(NULL)

{
	impl_ = new ATCLocker_impl();
}

Locker::~Locker()
{
	delete impl_;
	impl_ = NULL;
}

Result Locker::Open(Stream ^dst, array<System::Byte, 1> ^key)
{
	return static_cast<Result>(impl_->open(dst, key));
}

Result Locker::Open(Stream ^src, String ^key)
{
	return Locker::Open(src, Encoding::UTF8->GetBytes(key));
}

Result Locker::Close()
{
	return static_cast<Result>(impl_->close());
}

Result Locker::AddFileEntry(FileEntry ^entry)
{
	using namespace System::Runtime::InteropServices;
	ATCFileEntry entry_native;

	{
		char* str = (char*)(void*)Marshal::StringToHGlobalAnsi(entry->NameSJIS);
		entry_native.name_sjis = string(str);
		Marshal::FreeHGlobal(static_cast<System::IntPtr>(str));
	}

	{
		char* str = (char*)(void*)Marshal::StringToHGlobalAnsi(entry->NameUTF8);
		entry_native.name_utf8 = string(str);
		Marshal::FreeHGlobal(static_cast<System::IntPtr>(str));
	}

	entry_native.size = entry->Size;
	entry_native.attribute = entry->Attribute;

	entry_native.change_unix_time = dateTimeToUNIX(entry->ChangeDateTime);
	entry_native.create_unix_time = dateTimeToUNIX(entry->CreateDateTime);

	return static_cast<Result>(impl_->addFileEntry(entry_native));
}

Result Locker::WriteEncryptedHeader(Stream ^dst)
{
	return static_cast<Result>(impl_->writeEncryptedHeader(dst));
}

Result Locker::WriteFileData(Stream ^dst, Stream ^src, int64_t length)
{
	return static_cast<Result>(impl_->writeFileData(dst, src, length));
}

char Locker::PasswdTryLimit::get()
{
	return impl_->passwd_try_limit();
}

bool Locker::SelfDestruction::get()
{
	return impl_->self_destruction();
}

int32_t Locker::CompressionLevel::get()
{
	return impl_->compression_level();
}

DateTime^ Locker::CreateTime::get()
{
	return UNIXToDateTime(impl_->create_time());
}

void Locker::PasswdTryLimit::set(char passwd_try_limit)
{
	impl_->set_passwd_try_limit(passwd_try_limit);
}

void Locker::SelfDestruction::set(bool self_destruction)
{
	impl_->set_self_destruction(self_destruction);
}

void Locker::CompressionLevel::set(int32_t compression_level)
{
	impl_->set_compression_level(compression_level);
}

void Locker::CreateTime::set(DateTime ^create_time)
{
	impl_->set_create_time(dateTimeToUNIX(create_time));
}

}