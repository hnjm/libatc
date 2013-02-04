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
