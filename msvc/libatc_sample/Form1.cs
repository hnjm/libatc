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
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Collections;

namespace libatc_sample
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

            AllowDrop = true;
            DragEnter += new DragEventHandler(Form1_DragEnter);
            DragDrop += new DragEventHandler(Form1_DragDrop);
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void Form1_DragEnter(object s, DragEventArgs e)
        {
            string[] fileList = (string[])e.Data.GetData(DataFormats.FileDrop);
            
            // 単一ファイルまたはフォルダのドロップのみ許可
            if (fileList.Length == 1)
            {
                e.Effect = DragDropEffects.All;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void Form1_DragDrop(object s, DragEventArgs e)
        {
            string[] fileList = (string[])e.Data.GetData(DataFormats.FileDrop);

            // 複数ファイルまたはフォルダのドロップは無視
            if (fileList.Length != 1)
            {
                return;
            }


            bool encrypted = false;

            // 暗号化されたファイルかどうかチェック
            if (!Directory.Exists(fileList[0]))
            {
                using (FileStream outfs = new FileStream(fileList[0], FileMode.Open))
                {
                    var locker = new AttacheCase.Unlocker();
                    encrypted = (locker.Open(outfs) != AttacheCase.Result.ERR_UNENCRYPTED_FILE);
                }
            }

            if (encrypted)
            {
                Decrypt(fileList[0]);
            }
            else
            {
                Encrypt(fileList[0]);
            }
            
        }

        private void Decrypt(string fileName)
        {

            // パスワードの入力を要求
            PasswordInput form = new PasswordInput();
            form.ShowDialog();

            string key = form.GetPassword();
            if (key.Length > 0)
            {
                using (FileStream infs = new FileStream(fileName, FileMode.Open))
                {
                    var unlocker = new AttacheCase.Unlocker();

                    // 指定したキーで復号を試みる
                    AttacheCase.Result result = unlocker.Open(infs, key);

                    if (result == AttacheCase.Result.OK)
                    {
                        // *** ヘッダの復号に成功

                        foreach (AttacheCase.FileEntry entry in unlocker.Entries)
                        {
                            string dirPath = Path.GetDirectoryName(fileName);
                            string outName = dirPath + "\\" + entry.NameSJIS;

                            if (entry.Size < 0)
                            {
                                // *** ディレクトリ

                                // 無かったら作る
                                if (!Directory.Exists(outName))
                                {
                                    Directory.CreateDirectory(outName);
                                }

                                // 作成日時、更新日時を設定
                                Directory.SetCreationTime(outName, entry.CreateDateTime);
                                Directory.SetLastWriteTime(outName, entry.ChangeDateTime);
                            }
                            else
                            {
                                // *** ファイル

                                using (FileStream outfs = new FileStream(outName, FileMode.Create))
                                {
                                    unlocker.ExtractFileData(outfs, infs, entry.Size);   
                                }

                                // 作成日時、更新日時を設定
                                File.SetCreationTime(outName, entry.CreateDateTime);
                                File.SetLastWriteTime(outName, entry.ChangeDateTime);
                            }
                        }

                        MessageBox.Show("Decryption completed");

                    }
                    else if (result == AttacheCase.Result.ERR_WRONG_KEY)
                    {
                        // *** パスワードが違う

                        MessageBox.Show("Wrong password");
                    }
                    else
                    {
                        // *** 読み込み失敗

                        MessageBox.Show("Failed");
                    }
                }
            }
        }

        private void Encrypt(string inName)
        {

            // パスワードの入力を要求
            PasswordInput form = new PasswordInput();
            form.ShowDialog();

            // atcファイルの保存先の指定を要求
            SaveFileDialog dialog = new SaveFileDialog();
            dialog.Filter = "AttacheCase files (*.atc)|*.atc";
            dialog.FileName = "sample.atc";
            dialog.ShowDialog();

            string key = form.GetPassword();
            if (key.Length > 0)
            {

                // 暗号ファイルをオープン
                using (FileStream outfs = new FileStream(dialog.FileName, FileMode.Create))
                {

                    // 暗号ファイルをセットアップ、平文ヘッダを書き込み
                    var locker = new AttacheCase.Locker();
                    locker.Open(outfs, key);

                    Uri parentURI; 
                    ArrayList files = new ArrayList();

                    if (Directory.Exists(inName))
                    {
                        // *** ディレクトリ

                        // ディレクトリ以下のファイルをスキャンして追加
                        files.AddRange(Directory.GetFileSystemEntries(inName, "*.*", SearchOption.AllDirectories));

                        // ディレクトリ自身を含める
                        files.Add(inName);

                        // 相対パス計算用の絶対パス
                        parentURI = new Uri(inName);
                    }
                    else
                    {
                        // *** 単一ファイル

                        // ファイルを追加
                        files.Add(inName);

                        // 相対パス計算用の絶対パス
                        parentURI = new Uri(Directory.GetParent(inName).ToString() + "\\");
                    }

                    foreach (string fileName in files)
                    {

                        // ファイル属性を取得
                        FileAttributes attribute = File.GetAttributes(fileName);

                        Uri fileURI;
                        if (attribute == FileAttributes.Directory)
                        {
                            // *** ディレクトリ

                            // 末尾にバックスラッシュが必要
                            fileURI = new Uri(fileName + "\\");
                        }
                        else
                        {
                            // *** ファイル

                            fileURI = new Uri(fileName);
                        }

                        AttacheCase.FileEntry entry = new AttacheCase.FileEntry();

                        // エントリ名を指定
                        string relativepath = parentURI.MakeRelativeUri(fileURI).ToString();

                        // ディレクトリの区切りがスラッシュになっているので、
                        // 強制的にバックスラッシュへ変換する。
                        entry.NameUTF8 = relativepath.Replace('/', '\\');

                        // Shift-JISへ変換
                        entry.NameSJIS = Encoding.ASCII.GetString(
                            Encoding.Convert(Encoding.ASCII, Encoding.GetEncoding("Shift_JIS"),
                                Encoding.ASCII.GetBytes(entry.NameUTF8)));

                        // 作成日時、更新日時を設定
                        entry.CreateDateTime = File.GetCreationTime(fileName);
                        entry.ChangeDateTime = File.GetLastWriteTime(fileName);

                        // 属性を設定
                        entry.Attribute = (int)attribute;

                        if (attribute == FileAttributes.Directory)
                        {
                            // *** ディレクトリ

                            // ディレクトリのファイルサイズは-1
                            entry.Size = -1;
                        }
                        else
                        {
                            // *** ファイル

                            // ファイルサイズを取得して設定
                            using (FileStream infs = new FileStream(fileName, FileMode.Open))
                            {
                                entry.Size = infs.Length;
                            }
                        }

                        // エントリを追加
                        locker.AddFileEntry(entry);
                    }

                    // 暗号ヘッダを書き込み
                    locker.WriteEncryptedHeader(outfs);

                    // ファイルデータを書き込み
                    foreach (string fileName in files)
                    {

                        // ディレクトリは無視する
                        if (File.Exists(fileName))
                        {
                            using (FileStream infs = new FileStream(fileName, FileMode.Open))
                            {
                                locker.WriteFileData(outfs, infs, infs.Length);
                            }
                        }
                    }
                }
            }
        }
    }
}
