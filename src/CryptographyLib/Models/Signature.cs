using CryptographyLib.Helpers.Extensions;
using CryptographyLib.Helpers.OpenSslApi;

namespace CryptographyLib.Models
{
    internal class Signature
    {
        public IntPtr C { get; set; }
        public IntPtr S { get; set; }
        public IntPtr Y { get; set; }
        public IntPtr T { get; set; }

        public Signature(byte[] signature, OpenSslApiProvider openSslApiProvider)
        {
            var cArr = signature.Take(32).Reverse().ToArray().RemoveLeadingZeros();
            var sArr = signature.Skip(32).Take(32).Reverse().ToArray().RemoveLeadingZeros();
            var yArr = signature.Skip(64).Take(32).Reverse().ToArray().RemoveLeadingZeros();
            var arr = signature.Skip(96).Take(32).Reverse().ToArray().RemoveLeadingZeros();

            C = openSslApiProvider.BN_new();
            S = openSslApiProvider.BN_new();
            Y = openSslApiProvider.BN_new();
            T = openSslApiProvider.BN_new();

            if (IntPtr.Zero == (C = openSslApiProvider.BN_bin2bn(cArr, cArr.Length, IntPtr.Zero)))
            {
                C = IntPtr.Zero;
            }

            if (IntPtr.Zero == (S = openSslApiProvider.BN_bin2bn(sArr, sArr.Length, IntPtr.Zero)))
            {
                S = IntPtr.Zero;
            }

            if (IntPtr.Zero == (Y = openSslApiProvider.BN_bin2bn(yArr, yArr.Length, IntPtr.Zero)))
            {
                Y = IntPtr.Zero;
            }

            if (IntPtr.Zero == (T = openSslApiProvider.BN_bin2bn(arr, arr.Length, IntPtr.Zero)))
            {
                T = IntPtr.Zero;
            }
        }
    }
}
