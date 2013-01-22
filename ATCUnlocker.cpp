#include "ATCUnlocker.h"
#include "ATCUnlocker_impl.h"


ATCUnlocker::ATCUnlocker() :

impl_(NULL)

{
	impl_ = new ATCUnlocker_impl();
}

ATCUnlocker::~ATCUnlocker()
{
	if (impl_)
	{
		delete impl_;
		impl_ = NULL;
	}
}

ATCResult ATCUnlocker::open(istream *src, const char key[ATC_KEY_SIZE])
{
	return impl_->open(src, key);
}

ATCResult ATCUnlocker::close()
{
	return impl_->close();
}

size_t ATCUnlocker::getEntryLength() const
{
	return impl_->getEntryLength();
}

ATCResult ATCUnlocker::getEntry(ATCFileEntry *entry, size_t index)
{
	return impl_->getEntry(entry, index);
}

ATCResult ATCUnlocker::extractFileData(ostream *dst, istream *src, size_t length)
{
	return impl_->extractFileData(dst, src, length);
}

int32_t ATCUnlocker::data_version() const
{
	return impl_->data_version();
}

char ATCUnlocker::data_sub_version() const
{
	return impl_->data_sub_version();
}

int32_t ATCUnlocker::algorism_type() const
{
	return impl_->algorism_type();
}

char ATCUnlocker::passwd_try_limit() const
{
	return impl_->passwd_try_limit();
}

bool ATCUnlocker::self_destruction() const
{
	return impl_->self_destruction();
}
