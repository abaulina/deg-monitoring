using CryptographyLib.Helpers.CryptoApi;

namespace CryptographyLib.Helpers
{
    internal class Gost3410_2012_256CryptoServiceProvider
    {
        private readonly CryptoApiProvider _cryptoApiProvider;

        private IntPtr _hProv;

        public Gost3410_2012_256CryptoServiceProvider(CryptoApiProvider cryptoApiProvider)
        {
            _cryptoApiProvider = cryptoApiProvider;

            var b = _cryptoApiProvider.CryptAcquireContext(out var hProv, null, null, 80, 0xF0000000);
            b = _cryptoApiProvider.CryptSetProvParam(hProv, 95, CryptoProHelper.Gost34102012256CryptoProBParamSet, 0);
            _hProv = hProv;

        }

        public bool VerifySignature(byte[] publicKey, byte[] data, byte[] signature)
        {
            return VerifyHash(publicKey, data, signature);
        }

        public bool VerifyHash(byte[] publicKey, byte[] data, byte[] signature)
        {
            var b = _cryptoApiProvider.CryptImportKey(_hProv, publicKey, publicKey.Length, IntPtr.Zero, CryptoProHelper.PUBLICKEYBLOB, out IntPtr hPubKey);
            if (!b)
                return false;

            b = _cryptoApiProvider.CryptCreateHash(_hProv, 32801, IntPtr.Zero, 0, out var hHash);
            if (!b)
                return false;

            if (!_cryptoApiProvider.CryptHashData(hHash, data, data.Length, 0))
            {
                return false;
            }

            if (!_cryptoApiProvider.CryptVerifySignature(hHash, signature, CryptoProHelper.GfLen * 2, hPubKey, null, 0))
            {
                return false;
            }

            return true;
        }
    }
}
