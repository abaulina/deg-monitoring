using CryptographyLib.Helpers.CryptoApi;

namespace CryptographyLib.Helpers
{
    public class Gost3411_2012_256CryptoServiceProvider
    {
        private CryptoApiProvider _cryptoApiProvider;
        private IntPtr _hProv;
        public Gost3411_2012_256CryptoServiceProvider(CryptoApiProvider cryptoApiProvider)
        {
            _cryptoApiProvider = cryptoApiProvider;

            var b = _cryptoApiProvider.CryptAcquireContext(out var hProv, null, null, 80, 0xF0000000);
            _hProv = hProv;
            b = _cryptoApiProvider.CryptSetProvParam(_hProv, 95, CryptoProHelper.Gost34102012256CryptoProBParamSet, 0);
        }


        public byte[] ComputeHash(byte[] data)
        {
            var b = _cryptoApiProvider.CryptCreateHash(_hProv, 32801, IntPtr.Zero, 0, out var hHash);

            b = _cryptoApiProvider.CryptHashData(hHash, data, data.Length, 0);

            var hashSize = 32;

            var hashBytes = new byte[hashSize];
            b = _cryptoApiProvider.CryptGetHashParam(hHash, 2, hashBytes, ref hashSize, 0);

            return hashBytes;
        }
    }
}
