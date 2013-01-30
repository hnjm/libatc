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

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace libatc_cli_test
{
    [TestClass]
    public class libatc_cli_test
    {
        [TestMethod]
        public void SelfEncryptionAndDecryption()
        {

            string key = "This is a pen.";
            String atc_filename = "test_.atc";

            String test_data_str = "The quick brown fox jumps over the lazy dog";
            String test_data2_str = "Quo usque tandem abutere, Catilina, patientia nostra?";
            MemoryStream test_data = new MemoryStream(Encoding.ASCII.GetBytes(test_data_str));
            MemoryStream test_data2 = new MemoryStream(Encoding.ASCII.GetBytes(test_data2_str));

            // UNIX時間の精度に合わせるため切り捨てる
            DateTime time_stamp = (new DateTime()).AddSeconds(DateTime.Now.Ticks / 10000000);

            using (FileStream outfs = new FileStream(atc_filename, FileMode.Create))
            {
                AttacheCase.Locker locker = new AttacheCase.Locker();

                locker.PasswdTryLimit = 5;
                locker.SelfDestruction = true;

                Assert.AreEqual(locker.Open(outfs, key), AttacheCase.Result.OK);

                {
                    AttacheCase.FileEntry entry = new AttacheCase.FileEntry();
                    entry.Attribute = 16;
                    entry.Size = -1;
                    entry.NameSJIS = "out\\";
                    entry.NameUTF8 = "out\\";
                    entry.ChangeDateTime = time_stamp;
                    entry.CreateDateTime = time_stamp;
                    Assert.AreEqual(locker.AddFileEntry(entry), AttacheCase.Result.OK);
                }

                {
                    AttacheCase.FileEntry entry = new AttacheCase.FileEntry();
                    entry.Attribute = 0;
                    entry.Size = test_data.Length;
                    entry.NameSJIS = "out\\test.txt";
                    entry.NameUTF8 = "out\\test.txt";
                    entry.ChangeDateTime = time_stamp;
                    entry.CreateDateTime = time_stamp;
                    Assert.AreEqual(locker.AddFileEntry(entry), AttacheCase.Result.OK);
                }

                {
                    AttacheCase.FileEntry entry = new AttacheCase.FileEntry();
                    entry.Attribute = 0;
                    entry.Size = test_data2.Length;
                    entry.NameSJIS = "out\\test2.txt";
                    entry.NameUTF8 = "out\\test2.txt";
                    entry.ChangeDateTime = time_stamp;
                    entry.CreateDateTime = time_stamp;
                    Assert.AreEqual(locker.AddFileEntry(entry), AttacheCase.Result.OK);
                }

                Assert.AreEqual(locker.WriteEncryptedHeader(outfs), AttacheCase.Result.OK);
                Assert.AreEqual(locker.WriteFileData(outfs, test_data, (uint)test_data.Length), AttacheCase.Result.OK);
                Assert.AreEqual(locker.WriteFileData(outfs, test_data2, (uint)test_data2.Length), AttacheCase.Result.OK);

                Assert.AreEqual(locker.Close(), AttacheCase.Result.OK);

            }

            using (FileStream infs = new FileStream(atc_filename, FileMode.Open))
            {
                AttacheCase.Unlocker unlocker = new AttacheCase.Unlocker();

                Assert.AreEqual(unlocker.Open(infs, key), AttacheCase.Result.OK);
                Assert.AreEqual(unlocker.PasswdTryLimit, 5);
                Assert.IsTrue(unlocker.SelfDestruction);

                Assert.AreEqual(unlocker.Entries.Length, 3);

                {
                    AttacheCase.FileEntry entry = unlocker.Entries[1];

                    Assert.AreEqual(entry.ChangeDateTime, time_stamp);
                    Assert.AreEqual(entry.CreateDateTime, time_stamp);

                    MemoryStream buf = new MemoryStream();
                    Assert.AreEqual(unlocker.ExtractFileData(buf, infs, (uint)entry.Size), AttacheCase.Result.OK);

                    buf.Position = 0;
                    Assert.AreEqual((new StreamReader(buf)).ReadToEnd(), test_data_str);
                }

                {
                    AttacheCase.FileEntry entry = unlocker.Entries[2];

                    Assert.AreEqual(entry.ChangeDateTime, time_stamp);
                    Assert.AreEqual(entry.CreateDateTime, time_stamp);

                    MemoryStream buf = new MemoryStream();
                    Assert.AreEqual(unlocker.ExtractFileData(buf, infs, (uint)entry.Size), AttacheCase.Result.OK);

                    buf.Position = 0;
                    Assert.AreEqual((new StreamReader(buf)).ReadToEnd(), test_data2_str);
                }

            }

        }

        [TestMethod]
        public void Decryption_For_v1_46()
        {
            Decryption_Test("cosmos_v1.46.atc.tester");
        }

        [TestMethod]
        public void Decryption_For_v1_46_Executable()
        {
            Decryption_Test("cosmos_v1.46.exe.tester");
        }

        [TestMethod]
        public void Decryption_For_v2_7_5_0()
        {
            Decryption_Test("cosmos_v2.7.5.0.atc.tester");
        }

        [TestMethod]
        public void Decryption_For_v2_7_5_0_Executable()
        {
            Decryption_Test("cosmos_v2.7.5.0.exe.tester");
        }

        [TestMethod]
        public void Decryption_For_v2_8_2_5()
        {
            Decryption_Test("cosmos_v2.8.2.5.atc.tester");
        }

        [TestMethod]
        public void Decryption_For_v2_8_2_5_Executable()
        {
            Decryption_Test("cosmos_v2.8.2.5.exe.tester");
        }

        private static byte[] test_md5 = new byte[0];

        private void Decryption_Test(String filename)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();

	        string key = "cosmos";

	        if (test_md5.Length == 0)
	        {
                using (FileStream infs = new FileStream("../../../../test/cosmos.jpg", FileMode.Open))
                {
                    byte[] buffer = new byte[infs.Length];
                    infs.Read(buffer, 0, buffer.Length);
                    md5.ComputeHash(buffer);
                    test_md5 = md5.Hash;
                    md5.Initialize();
                }
	        }

            using (FileStream infs = new FileStream("../../../../test/" + filename, FileMode.Open))
            {
                AttacheCase.Unlocker unlocker = new AttacheCase.Unlocker();
                Assert.AreEqual(unlocker.Open(infs, key), AttacheCase.Result.OK);
                Assert.AreEqual(unlocker.Entries.Length, 1);

                AttacheCase.FileEntry entry = unlocker.Entries[0];

                MemoryStream extracted = new MemoryStream();
                Assert.AreEqual(unlocker.ExtractFileData(extracted, infs, (uint)entry.Size), AttacheCase.Result.OK);

                byte[] buffer = new byte[entry.Size];
                extracted.Position = 0;
                extracted.Read(buffer, 0, buffer.Length);

                md5.ComputeHash(buffer);
                Assert.IsTrue(test_md5.SequenceEqual(md5.Hash));
            }

        }


    }
}
