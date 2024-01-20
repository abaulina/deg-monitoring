using CryptographyLib.Helpers.CryptoApi;
using System.Text;

namespace CryptographyLib.Helpers
{
    public class DegHash
    {
        public static byte[] Dst = Encoding.UTF8.GetBytes("BlindSign-TeZhu-V00-H2F:id-tc26-gost-3410-2012-256-paramSetB_Streebog-256_XMD_ROP");
        public const int L = 48;
        public const int Ll = 2;
        public const byte Mask = 0xFF;
        public const byte TmpB0 = L & Mask;
        public const byte TmpB1 = L >> 8;
        public const byte Zero = 0;
        private Gost3411_2012_256CryptoServiceProvider _stribog;

        public DegHash(CryptoApiProvider cryptoApiProvider)
        {
            _stribog = new Gost3411_2012_256CryptoServiceProvider(cryptoApiProvider);
        }

        public byte[] Hash(byte[] msg)
        {
            var bb = new byte[64 + msg.Length + 3 + Dst.Length];
            msg.CopyTo(bb, 64);
            bb[64 + msg.Length] = TmpB1;
            bb[64 + msg.Length + 1] = TmpB0;
            bb[64 + msg.Length + 2] = Zero;
            Dst.CopyTo(bb, 64 + msg.Length + 3);

            var firstRoundHash = _stribog.ComputeHash(bb);

            var h = Convert.ToHexString(firstRoundHash);

            var nextRoundHash = new byte[32];
            var resultBuffer = Array.Empty<byte>();

            for (var i = 1; i <= Ll; i++)
            {
                var xored = Xor(nextRoundHash, firstRoundHash);
                var internalBb = new byte[xored.Length + 1 + Dst.Length];
                xored.CopyTo(internalBb, 0);
                internalBb[xored.Length] = (byte)i;
                Dst.CopyTo(internalBb, xored.Length + 1);

                nextRoundHash = _stribog.ComputeHash(internalBb);

                resultBuffer = resultBuffer.Concat(nextRoundHash).ToArray();
            }

            var result = new byte[L];
            Array.Copy(resultBuffer, result, L);
            return result;
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                throw new ArgumentException("Arrays must be of the same length");
            }

            var result = new byte[a.Length];
            for (var i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }
    }
}
