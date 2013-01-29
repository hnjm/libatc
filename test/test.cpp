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

#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <stdexcept>

#include "../ATCUnlocker.h"
#include "../ATCLocker.h"

extern "C"
{
#include "crc.h"
}

#ifdef WIN32
	#ifdef _DEBUG
		#pragma comment(lib, "zlib_d.lib")
	#else
		#pragma comment(lib, "zlib.lib")
	#endif
	#pragma comment(lib, "libatc.lib")
#endif

using namespace std;

string test_path = "./test/";


int total = 0;
int succeeded = 0;

#define ASSERT(expression) \
{ \
	if (!(expression)) \
	{ \
		cout << "\tFailed: line " << __LINE__ << " : " << #expression << endl; \
		return false; \
	} \
}

#define TEST(function) \
{ \
	total++; \
	cout << endl << "[Test " << total << "] " << #function << endl; \
	if (!function()) \
	{ \
		cout << "\t*** FAILED ***" << endl << endl; \
	} else { \
		cout << "\t*** OK ***" << endl << endl; \
		succeeded++; \
	} \
}


// Tests
bool Self_Encryption_And_Decryption();
bool Decryption_For_v1_46();
bool Decryption_For_v1_46_Executable();
bool Decryption_For_v2_7_5_0();
bool Decryption_For_v2_7_5_0_Executable();
bool Decryption_For_v2_8_2_5();
bool Decryption_For_v2_8_2_5_Executable();

int main()
{

#ifdef WIN32
	test_path = "../../test/";
#endif
    
#ifdef __APPLE__
    test_path = string(__FILE__);
    test_path.replace(test_path.find_last_of('/'), string::npos, "/");
#endif

	TEST(Self_Encryption_And_Decryption);
	TEST(Decryption_For_v1_46);
	TEST(Decryption_For_v1_46_Executable);
	TEST(Decryption_For_v2_7_5_0);
	TEST(Decryption_For_v2_7_5_0_Executable);
	TEST(Decryption_For_v2_8_2_5);
	TEST(Decryption_For_v2_8_2_5_Executable);

	cout << "---------------------" << endl;
	cout << "Result: " << succeeded << "/" << total << endl;

	if (succeeded == total)
	{
		cout << "All Tests Passed" << endl << endl;
		return EXIT_SUCCESS;
	} else {
		cout << "*** Test Failed ***" << endl << endl;
		return EXIT_FAILURE;
	}

}


bool Self_Encryption_And_Decryption()
{
	char key[ATC_KEY_SIZE] = "This is a pen.";
	char atc_filename[] = "test_.atc";

	stringstream test_data("The quick brown fox jumps over the lazy dog");
	stringstream test_data2("Quo usque tandem abutere, Catilina, patientia nostra?");
	time_t time_stamp = time(NULL);

	{
		ATCLocker locker;

		locker.set_passwd_try_limit(5);
		locker.set_self_destruction(true);

		ofstream ofs(test_path + atc_filename, ifstream::binary);
		ASSERT(ofs);
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
		ifstream ifs(test_path + atc_filename, ifstream::binary);
		ASSERT(ifs);

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

	return true;
}

bool Decryption_Test(const char *filename)
{
	char key[ATC_KEY_SIZE] = "cosmos";

	static unsigned short test_crc = 0;
	if (test_crc == 0)
	{
		ifstream ifs(test_path + "cosmos.jpg", ifstream::binary);

		ifs.seekg(0, ios::end);
		size_t length = ifs.tellg();
		ifs.seekg(0, ios::beg);

		char *buffer = new char[length];
		ifs.read(buffer, length);

		crcInit();
		test_crc = crcFast(reinterpret_cast<const unsigned char*>(buffer), length);

		delete[] buffer;
	}

	ifstream ifs(test_path + filename, ifstream::binary);
	ASSERT(ifs);

	ATCUnlocker unlocker;
	ASSERT(unlocker.open(&ifs, key) == ATC_OK);
	ASSERT(unlocker.getEntryLength() == 1);

	{
		ATCFileEntry entry;
		ASSERT(unlocker.getEntry(&entry, 0) == ATC_OK);

		stringstream buffer;
		ASSERT(unlocker.extractFileData(&buffer, &ifs, entry.size) == ATC_OK);

		crcInit();
		unsigned short crc = 
			crcFast(reinterpret_cast<const unsigned char*>(buffer.str().data()), buffer.str().size());

		ASSERT(test_crc == crc);
	}

	return true;
}

bool Decryption_For_v1_46()
{
	return Decryption_Test("cosmos_v1.46.atc.tester");
}

bool Decryption_For_v1_46_Executable()
{
	return Decryption_Test("cosmos_v1.46.exe.tester");
}

bool Decryption_For_v2_7_5_0()
{
	return Decryption_Test("cosmos_v2.7.5.0.atc.tester");
}

bool Decryption_For_v2_7_5_0_Executable()
{
	return Decryption_Test("cosmos_v2.7.5.0.exe.tester");
}

bool Decryption_For_v2_8_2_5()
{
	return Decryption_Test("cosmos_v2.8.2.5.atc.tester");
}

bool Decryption_For_v2_8_2_5_Executable()
{
	return Decryption_Test("cosmos_v2.8.2.5.exe.tester");
}

#undef ASSERT
#undef TEST