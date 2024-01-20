using CryptographyLib.Helpers;
using CryptographyLib.Helpers.Extensions;
using CryptographyLib.Helpers.OpenSslApi;

namespace CryptographyLib.Models
{
    internal class PublicKey
    {
        public IntPtr Q { get; } = IntPtr.Zero;
        public IntPtr Z { get; } = IntPtr.Zero;

        public PublicKey(byte[] publicKey, CryptoProHelper cryptoProHelper, OpenSslApiProvider openSslApiProvider)
        {
            var Q_LE = publicKey.Skip(2).Take(64);
            var Z_LE = publicKey.Skip(66).Take(64);

            var Q_BE =
                $"04{Convert.ToHexString(Q_LE.Take(32).Reverse().ToArray())}{Convert.ToHexString(Q_LE.Skip(32).Take(32).Reverse().ToArray())}";
            var Z_BE =
                $"04{Convert.ToHexString(Z_LE.Take(32).Reverse().ToArray())}{Convert.ToHexString(Z_LE.Skip(32).Take(32).Reverse().ToArray())}";

            var qArr = Q_BE.HexToByteArray();
            var zArr = Z_BE.HexToByteArray();

            var pCurve = cryptoProHelper.create_curve();
            var qPoint = openSslApiProvider.EC_POINT_new(pCurve);
            cryptoProHelper.CreateEcPoint(pCurve, qArr, qPoint);
            Q = qPoint;

            var zPoint = openSslApiProvider.EC_POINT_new(pCurve);
            cryptoProHelper.CreateEcPoint(pCurve, zArr, zPoint);
            Z = zPoint;

            openSslApiProvider.EC_GROUP_free(pCurve);
        }
    }
}