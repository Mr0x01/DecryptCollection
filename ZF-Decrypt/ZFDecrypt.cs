using System;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace ZFDecrypt
{
    public partial class DecryptUtil
    {
        public static int getAscii(string s)
        {
            byte[] array = System.Text.Encoding.ASCII.GetBytes(s);
            return (int)(array[0]);
        }

        static string my_reverse(string original)
        {
            char[] arr = original.ToCharArray();
            Array.Reverse(arr);
            return new string(arr);
        }

        public static string Decrypt(string PlainStr)
        {
            string key = "Encrypt01";//密钥
            int num = 1;
            checked
            {
                if (PlainStr.Length % 2 == 0)
                {
                    string text = my_reverse(PlainStr.Substring(0,(int)Math.Round((double)PlainStr.Length/ 2.0))).ToString();
                    Console.WriteLine(text + "前段");
                    string text2 = (my_reverse(PlainStr).ToString().Substring(0, (int)Math.Round((double)PlainStr.Length / 2.0)));
                    Console.WriteLine(text2 + "后段");
                    PlainStr = text + text2;
                    Console.WriteLine(PlainStr+"偶数位处理结果");
                }
                int num2 = PlainStr.Length;
                string text5 = "";
                for (int i = 0; i < num2; i++)
                {
                    string text3 = PlainStr.Substring(i, 1);
                    string text4 = key.Substring(num-1, 1);
                    if ((getAscii(text3) ^ getAscii(text4)) < 32 | (getAscii(text3) ^ getAscii(text4)) > 126 | getAscii(text3) < 0 | getAscii(text3) > 255)
                    {
                        //Console.WriteLine(getAscii(text3) ^ getAscii(text4));
                        text5 += text3;
                        Console.WriteLine(text5 + "出自if①");
                    }
                    else
                    {
                        text5 += Convert.ToChar(getAscii(text3) ^ getAscii(text4)).ToString();
                        Console.WriteLine(text5 + "出自if②");
                    }
                    if (num == key.Length)
                    {
                        num = 0;
                    }
                    num++;
                }
                return text5;
            }
        }
    }
}
