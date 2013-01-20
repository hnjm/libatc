#include <iostream>
#include <ctime>

#include "../ATCUnlocker.h"
#include "../ATCLocker.h"

#ifdef WIN32
	#ifdef _DEBUG
		#pragma comment(lib, "zlib_d.lib")
	#else
		#pragma comment(lib, "zlib.lib")
	#endif
	#pragma comment(lib, "libatc.lib")
#endif

using namespace std;

#define ASSERT(expression) \
{ \
	if (!(expression)) \
	{ \
		cout << "Assertion failed in line " << __LINE__ << " : " << #expression << endl; \
		cout << "*** FAILED ***" << endl; \
		exit(EXIT_FAILURE); \
	} else \
	{ \
		cout << "PASS:\t" << #expression << endl; \
	} \
}

int main()
{
	char key[ATC_KEY_SIZE]	= "This is a pen.";
	char atc_filename[]		= "test_.atc";

	stringstream test_data("The quick brown fox jumps over the lazy dog");
	stringstream test_data2("Quo usque tandem abutere, Catilina, patientia nostra?");
	time_t time_stamp = time(NULL);

	{
		ATCLocker locker;

		locker.set_passwd_try_limit(5);
		locker.set_self_destruction(true);

		ofstream ofs(atc_filename, ifstream::binary);
		ASSERT(locker.open(&ofs, key) == ATC_OK);

		{
			ATCFileEntry entry;
				entry.attribute = 16;
				entry.size = -1;
				entry.name_sjis = "out\\";
				entry.name_utf8 = "out\\";
				entry.change_unix_time = time_stamp;
				entry.create_unix_time = time_stamp;
				ASSERT(locker.addFileEntry(entry) == ATC_OK);
		}

		{
			ATCFileEntry entry;
				entry.attribute = 0;
				entry.size = test_data.str().size();
				entry.name_sjis = "out\\test.txt";
				entry.name_utf8 = "out\\test.txt";
				entry.change_unix_time = time_stamp;
				entry.create_unix_time = time_stamp;
				ASSERT(locker.addFileEntry(entry) == ATC_OK);
		}

		{
			ATCFileEntry entry;
				entry.attribute = 0;
				entry.size = test_data2.str().size();
				entry.name_sjis = "out\\test2.txt";
				entry.name_utf8 = "out\\test2.txt";
				entry.change_unix_time = time_stamp;
				entry.create_unix_time = time_stamp;
				ASSERT(locker.addFileEntry(entry) == ATC_OK);
		}

		ASSERT(locker.writeEncryptedHeader(&ofs) == ATC_OK);
		ASSERT(locker.writeFileData(&ofs, &test_data,  test_data.str().size()) == ATC_OK);
		ASSERT(locker.writeFileData(&ofs, &test_data2, test_data2.str().size()) == ATC_OK);

		ASSERT(locker.close() == ATC_OK);
	}

	{
		ATCUnlocker unlocker;
		ifstream ifs(atc_filename, ifstream::binary);

		ASSERT(unlocker.open(&ifs, key) == ATC_OK);
		ASSERT(unlocker.passwd_try_limit() == 5);
		ASSERT(unlocker.self_destruction() == true);

		ASSERT(unlocker.getEntryLength() == 3);

		{
			ATCFileEntry entry;
			ASSERT(unlocker.getEntry(&entry, 1) == ATC_OK);

			ASSERT(entry.change_unix_time == time_stamp);
			ASSERT(entry.create_unix_time == time_stamp);

			stringstream out;
			ASSERT(unlocker.extractFileData(&out, &ifs, entry.size) == ATC_OK);
			ASSERT(out.str() == test_data.str());
		}

		{
			ATCFileEntry entry;
			ASSERT(unlocker.getEntry(&entry, 2) == ATC_OK);

			ASSERT(entry.change_unix_time == time_stamp);
			ASSERT(entry.create_unix_time == time_stamp);

			stringstream out;
			ASSERT(unlocker.extractFileData(&out, &ifs, entry.size) == ATC_OK);
			ASSERT(out.str() == test_data2.str());
		}

	}

	cout << "*** SUCCEEDED ***" << endl;

	return 0;
}

#undef ASSERT