using System.Runtime.InteropServices;

namespace CryptographyLib.Helpers.CryptoApi
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_DATA_BLOB
    {
        public int cbData; // Length of the data in bytes
        public IntPtr pbData; // Pointer to the data
    }
}
