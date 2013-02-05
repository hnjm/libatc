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

namespace libatc_sample
{
    public partial class PasswordInput : Form
    {
        public PasswordInput()
        {
            InitializeComponent();

            FormBorderStyle = FormBorderStyle.FixedDialog;

            textBox1.PasswordChar = '*';
            textBox1.Focus();
            button1.Enabled = false;
        }

        private void PasswordInput_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        public string GetPassword()
        {
            return this.textBox1.Text;
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            button1.Enabled = (textBox1.Text.Length > 0);
        }
    }
}
