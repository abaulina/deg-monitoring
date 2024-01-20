using CryptographyLib.Helpers.CryptoApi;
using CryptographyLib.Helpers.Extensions;
using CryptographyLib.Helpers.OpenSslApi;
using CryptographyLib.Models;
using SimpleBase;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptographyLib.Helpers
{
    public class CryptoProHelper
    {
        private CryptoApiProvider _cryptoApiProvider;
        private OpenSslApiProvider _openSslApiProvider;
        public CryptoProHelper()
        {
            _cryptoApiProvider = new CryptoApiProvider();
            _openSslApiProvider = new OpenSslApiProvider();
        }

        public const int GfLen = 32;
        private const int PUB_BLOB_EXPORT_HEADER_LEN = 37;
        private const int PUB_BLOB_EXPORT_LEN = PUB_BLOB_EXPORT_HEADER_LEN + 64;

        private const int EC_PLUS = 0;
        private const int EC_MINUS = 1;

        private const uint KP_MULX = 0x800000f1;
        private const uint KP_ADDX = 0x800000f3;
        private const int KP_HANDLE = 46;
        private const int PP_DHOID = 95;
        public const int PUBLICKEYBLOB = 0x6;
        private const int CP_CRYPT_DATA_HANDLE = 0x00000010;

        public const string BaseCompressed = "020000000000000000000000000000000000000000000000000000000000000001";

        public const string X = "0000000000000000000000000000000000000000000000000000000000000001";
        public const string Y = "8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14";
        public const string Base = $"04{X}{Y}";

        public const string Gost34102012256CryptoProBParamSet = "1.2.643.7.1.2.1.1.2";

        private int _pubBlobExportCompressedLen = PUB_BLOB_EXPORT_HEADER_LEN + 32 + 1;

        public int Point2HexCompressedEx(byte[] pBx, byte flagB, out string pszPoint)
        {
            var err = 1;
            pszPoint = string.Empty;
            string pPoint;
            pPoint = flagB == 0 ? "02" : "03";

            foreach (var b in pBx)
            {
                var szHexByte = b.ToString("X2");
                pPoint += szHexByte;
            }

            pszPoint = pPoint.ToLower();
            return err;
        }

        public bool ScalarMultCompressedBe2Handle(IntPtr hProv, byte[] pNum, byte[]? pPoint, byte ubPointFlag, out IntPtr phKey)
        {
            phKey = IntPtr.Zero;

            var b = ScalarMultCompressedBe(hProv, pNum, pPoint, ubPointFlag, out var pResultX, out var flagResult);
            if (!b)
            {
                return false;
            }

            b = ImportPointCompressedBe(hProv, pResultX, flagResult, out phKey);

            if (!b)
            {
                return false;
            }

            return b;
        }

        public bool ScalarMultCompressedBe(IntPtr hProv, byte[] pNum, byte[] pPoint, byte ubPointFlag, out byte[] pResultPoint, out byte ubResultPointFlag)
        {
            bool b;

            pResultPoint = new byte[GfLen];
            var pPointLe = new byte[GfLen + 1];
            var pResultPointLe = new byte[GfLen + 1];
            var pNumLe = new byte[GfLen];

            Array.Copy(pNum, pNumLe, GfLen);
            Array.Reverse(pNumLe);

            if (pPoint != null)
            {
                Array.Copy(pPoint, pPointLe, GfLen);
                Array.Reverse(pPointLe, 0, GfLen);
                pPointLe[GfLen] = ubPointFlag;

                b = ScalarMultCompressed2(hProv, pNumLe, pPointLe, out pResultPointLe);

            }
            else
            {
                b = ScalarMultCompressed2(hProv, pNumLe, null, out pResultPointLe);
            }

            Array.Copy(pResultPointLe, pResultPoint, GfLen);
            Array.Reverse(pResultPoint);

            ubResultPointFlag = pResultPointLe[GfLen];

            if (!b)
            {
                return false;
            }

            return b;
        }

        public bool ScalarMultCompressed2(IntPtr hProv, byte[] pNum, byte[] pPoint, out byte[] pResultPoint)
        {
            var pbData = Marshal.AllocHGlobal(pNum.Length);
            Marshal.Copy(pNum, 0, pbData, pNum.Length);

            var blob = new CRYPT_DATA_BLOB();
            blob.cbData = pNum.Length;
            blob.pbData = pbData;

            var pbKeyBlob = new byte[PUB_BLOB_EXPORT_LEN];
            pResultPoint = new byte[GfLen + 1];
            var pBaseCompressed = new byte[32 + 1]
            {
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02,
            };

            var b = _cryptoApiProvider.CryptSetProvParam(hProv, PP_DHOID, Gost34102012256CryptoProBParamSet, 0);
            if (!b)
                return false;

            if (pPoint == null)
                pPoint = pBaseCompressed;

            b = ImportPointCompressedLe(hProv, pPoint, pPoint[32], out var hKey);
            if (!b)
                return false;

            unsafe
            {
                // Получим в hKey ( (m * sk) mod q, m * pk)
                b = _cryptoApiProvider.CryptSetKeyParam(hKey, KP_MULX, &blob, 0);
            }

            if (!b)
                return false;

            // Экспортирование открытого ключа получателя в BLOB открытого ключа.
            if (!_cryptoApiProvider.CryptExportKey(hKey, IntPtr.Zero, 0x6, 0x00000800, pbKeyBlob, ref _pubBlobExportCompressedLen))
            {
                return false;
            }

            Array.Copy(pbKeyBlob, 29, pResultPoint, 0, 32 + 1);

            return b;
        }

        public bool ImportPointCompressedLe(IntPtr hProv, byte[] pX, byte ubOddFlag, out IntPtr hKey)
        {
            var pPubKeyBlobCompressed = new byte[29 + 32 + 1];

            byte[] pPubKeyBlobHeader =
            {
                0x06, 0x20, 0x00, 0x00, 0x49,
                0x2E, 0x00, 0x00, 0x4D, 0x41,
                0x47, 0x31, 0x08, 0x01, 0x00,
                0x00, 0x30, 0x0B, 0x06, 0x09,
                0x2A, 0x85, 0x03, 0x07, 0x01,
                0x02, 0x01, 0x01, 0x02,
            };
            Array.Copy(pPubKeyBlobHeader, pPubKeyBlobCompressed, pPubKeyBlobHeader.Length);
            Array.Copy(pX, 0, pPubKeyBlobCompressed, 29, 32);
            pPubKeyBlobCompressed[29 + 32] = ubOddFlag;

            var b = _cryptoApiProvider.CryptImportKey(hProv, pPubKeyBlobCompressed, pPubKeyBlobCompressed.Length, IntPtr.Zero,
                PUBLICKEYBLOB, out hKey);

            if (!b)
            {
                var err = Marshal.GetLastWin32Error();
            }

            return b;
        }

        public bool ImportPointCompressedBe(IntPtr hProv, byte[] pX, byte ubOddFlag, out IntPtr hKey)
        {
            var pXLe = new byte[GfLen];
            Array.Copy(pX, pXLe, GfLen);
            Array.Reverse(pXLe);

            return ImportPointCompressedLe(hProv, pXLe, ubOddFlag, out hKey);
        }

        public bool AddPointsCryptoPro(IntPtr hKey1, IntPtr hKey2)
        {
            return AddOrSubtractPointsCryptoPro(hKey1, hKey2, true);
        }

        public bool AddOrSubtractPointsCryptoPro(IntPtr hKey1, IntPtr hKey2, bool isAdd)
        {
            var hAddHandle = IntPtr.Zero;

            var dwHandleSize = Marshal.SizeOf(hAddHandle);
            var cdbNum = new CRYPT_DATA_BLOB();

            var b = _cryptoApiProvider.CryptGetKeyParam(hKey2, KP_HANDLE, ref hAddHandle, ref dwHandleSize, 0);
            var err = Marshal.GetLastWin32Error();
            if (!b)
                return false;

            cdbNum.cbData = Marshal.SizeOf(hAddHandle);

            var hAddHandlePtr = Marshal.AllocHGlobal(cdbNum.cbData);

            Marshal.StructureToPtr(hAddHandle, hAddHandlePtr, false);

            cdbNum.pbData = hAddHandlePtr;

            unsafe
            {
                b = _cryptoApiProvider.CryptSetKeyParam(hKey1, KP_ADDX, &cdbNum, (isAdd ? EC_PLUS : EC_MINUS) | CP_CRYPT_DATA_HANDLE);
            }
            if (!b)
                return false;

            return b;
        }

        public bool IsPubKeysEqual(IntPtr hKeyA2, IntPtr hKeyA1)
        {
            var pbKeyBlob1 = new byte[29 + 2 * GfLen];
            var pbKeyBlob2 = new byte[29 + 2 * GfLen];
            var dwBlobLen = 29 + 2 * GfLen;

            if (!_cryptoApiProvider.CryptExportKey(hKeyA1, IntPtr.Zero, PUBLICKEYBLOB, 0, pbKeyBlob1, ref dwBlobLen))
                return false;

            if (!_cryptoApiProvider.CryptExportKey(hKeyA2, IntPtr.Zero, PUBLICKEYBLOB, 0, pbKeyBlob2, ref dwBlobLen))
                return false;

            if (Equals(pbKeyBlob2, pbKeyBlob1))
                return false;
            return true;
        }

        public byte[] PublicKeyCombine(List<byte[]> points, out byte[] result)
        {
            result = new byte[GfLen + 1];

            var bytes = points.Aggregate((a, b) => a.Concat(b).ToArray());

            if (PublicKeyCombine(bytes, points.Count, out result) != 1)
            {
                throw new Exception("Unknown wrapper error");
            }

            return result;
        }


        // from curve.c
        public int PublicKeyCombine(byte[] points, int num, out byte[] result)
        {
            result = new byte[GfLen + 1];
            var err = 1;
            IntPtr pCurve = IntPtr.Zero,
                ctx = IntPtr.Zero,
                acc = IntPtr.Zero,
                point = IntPtr.Zero;

            byte flagAcc = 0, flagPoint = 0, resFlag = 0;
            var pointX = new byte[GfLen];
            var accX = new byte[GfLen];

            ctx = _openSslApiProvider.BN_CTX_new();

            pCurve = create_curve();

            if (pCurve == IntPtr.Zero)
            {
                err = 0;
                goto exit;
            }

            acc = _openSslApiProvider.EC_POINT_new(pCurve);

            for (var i = 0; i < GfLen; i++)
            {
                accX[i] = points[i + 1];
            }
            if (points[0] == 0x02)
            {
                flagAcc = 0;
            }
            else if (points[0] == 0x03)
            {
                flagAcc = 1;
            }

            err = binBE2EC_POINTCompressed(pCurve, accX, flagAcc, acc);
            if (err != 1)
                goto exit;


            point = _openSslApiProvider.EC_POINT_new(pCurve);
            for (var offset = GfLen + 1; offset < num * (GfLen + 1); offset += GfLen + 1)
            {
                for (var i = 0; i < GfLen; i++)
                {
                    pointX[i] = points[offset + i + 1];
                }

                if (points[offset] == 0x02)
                {
                    flagPoint = 0;
                }
                else if (points[offset] == 0x03)
                {
                    flagPoint = 1;
                }

                err = binBE2EC_POINTCompressed(pCurve, pointX, flagPoint, point);
                if (err != 1)
                    goto exit;

                err = _openSslApiProvider.EC_POINT_add(pCurve, acc, point, acc, ctx);
                if (err != 1)
                    goto exit;
            }

            err = EC_POINT2binBECompressed(pCurve, acc, out result, out flagAcc);
            if (err != 1)
                goto exit;


            if (flagAcc == 0)
            {
                result[0] = 0x02;
            }
            else
            {
                result[0] = 0x03;
            }

            exit:
            _openSslApiProvider.EC_POINT_free(acc);
            _openSslApiProvider.EC_POINT_free(point);
            _openSslApiProvider.EC_GROUP_free(pCurve);

            _openSslApiProvider.BN_CTX_free(ctx);

            return err;
        }

        public byte[] ABin = {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0x94,
        };

        public byte[] BBin = { 0xA6 };

        public byte[] PBin =
                {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0x97,
        };

        public byte[] OrderBin =     {
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0x6C, 0x61, 0x10, 0x70, 0x99, 0x5A, 0xD1, 0x00, 0x45, 0x84, 0x1B, 0x09, 0xB7, 0x61, 0xB8, 0x93,
        };

        public byte[] XBin = { 0x01 };

        public byte[] YBin =
                {
                0x8D, 0x91, 0xE4, 0x71, 0xE0, 0x98, 0x9C, 0xDA, 0x27, 0xDF, 0x50, 0x5A, 0x45, 0x3F, 0x2B, 0x76,
                0x35, 0x29, 0x4F, 0x2D, 0xDF, 0x23, 0xE3, 0xB1, 0x22, 0xAC, 0xC9, 0x9C, 0x9E, 0x9F, 0x1E, 0x14,
        };

        public IntPtr create_curve()
        {
            IntPtr ctx = IntPtr.Zero;

            IntPtr curve;
            IntPtr a, b, p, order, x, y;
            IntPtr generator;

            try
            {

                /* Set up the BN_CTX */
                if (IntPtr.Zero == (ctx = _openSslApiProvider.BN_CTX_new())) return IntPtr.Zero;
            }
            catch (Exception ex)
            { Console.WriteLine(ex); }
            /* Set the values for the various parameters */

            if (IntPtr.Zero == (a = _openSslApiProvider.BN_bin2bn(ABin, ABin.Length, IntPtr.Zero))) return IntPtr.Zero;
            if (IntPtr.Zero == (b = _openSslApiProvider.BN_bin2bn(BBin, BBin.Length, IntPtr.Zero))) return IntPtr.Zero;
            if (IntPtr.Zero == (p = _openSslApiProvider.BN_bin2bn(PBin, PBin.Length, IntPtr.Zero))) return IntPtr.Zero;
            if (IntPtr.Zero == (order = _openSslApiProvider.BN_bin2bn(OrderBin, OrderBin.Length, IntPtr.Zero))) return IntPtr.Zero;
            if (IntPtr.Zero == (x = _openSslApiProvider.BN_bin2bn(XBin, XBin.Length, IntPtr.Zero))) return IntPtr.Zero;
            if (IntPtr.Zero == (y = _openSslApiProvider.BN_bin2bn(YBin, YBin.Length, IntPtr.Zero))) return IntPtr.Zero;

            /*
                PrintBN(a);
                PrintBN(b);
                PrintBN(p);
                PrintBN(order);
                PrintBN(x);
                PrintBN(y);
            */

            /* Create the curve */
            if (IntPtr.Zero == (curve = _openSslApiProvider.EC_GROUP_new_curve_GFp(p, a, b, ctx))) return IntPtr.Zero;

            /* Create the generator */
            if (IntPtr.Zero == (generator = _openSslApiProvider.EC_POINT_new(curve)))
                return IntPtr.Zero;

            if (1 != _openSslApiProvider.EC_POINT_set_affine_coordinates_GFp(curve, generator, x, y, ctx))
                return IntPtr.Zero;

            /* Set the generator and the order */
            if (1 != _openSslApiProvider.EC_GROUP_set_generator(curve, generator, order, IntPtr.Zero))
                return IntPtr.Zero;

            _openSslApiProvider.EC_POINT_free(generator);
            _openSslApiProvider.BN_free(y);
            _openSslApiProvider.BN_free(x);
            _openSslApiProvider.BN_free(order);
            _openSslApiProvider.BN_free(p);
            _openSslApiProvider.BN_free(b);
            _openSslApiProvider.BN_free(a);
            _openSslApiProvider.BN_CTX_free(ctx);

            return curve;
        }

        public int binBE2EC_POINTCompressed(IntPtr pCurve, byte[] pX, byte flag, IntPtr pPoint)
        {
            var err = 1;

            IntPtr bnX;

            if (IntPtr.Zero == (bnX = _openSslApiProvider.BN_bin2bn(pX, GfLen, IntPtr.Zero)))
                goto exit;

            err = _openSslApiProvider.EC_POINT_set_compressed_coordinates_GFp(pCurve, pPoint, bnX, flag, IntPtr.Zero);

            if (err != 1)
            {
                goto exit;
            }

            exit:
            _openSslApiProvider.BN_free(bnX);

            return err;
        }


        public int binBE2EC_POINTUncompressed(IntPtr pCurve, byte[] pX, byte[] pY, IntPtr pPoint)
        {
            var err = 1;

            var bnX = IntPtr.Zero;
            var bnY = IntPtr.Zero;

            if (IntPtr.Zero == (bnX = _openSslApiProvider.BN_bin2bn(pX, GfLen, IntPtr.Zero)))
                goto exit;
            if (IntPtr.Zero == (bnY = _openSslApiProvider.BN_bin2bn(pY, GfLen, IntPtr.Zero)))
                goto exit;

            err = _openSslApiProvider.EC_POINT_set_affine_coordinates_GFp(pCurve, pPoint, bnX, bnY, IntPtr.Zero);
            if (err != 1)
            {
                goto exit;
            }

            err = _openSslApiProvider.EC_POINT_is_on_curve(pCurve, pPoint, IntPtr.Zero);
            if (err != 1)
                return err;


            exit:
            _openSslApiProvider.BN_free(bnX);
            _openSslApiProvider.BN_free(bnY);

            return err;
        }


        public int EC_POINT2binBECompressed(IntPtr pCurve, IntPtr pPoint, out byte[] pPointX, out byte pFlag)
        {
            pPointX = new byte[GfLen];
            var err = 1;

            pFlag = 0;

            IntPtr bnX, bnY;

            bnX = _openSslApiProvider.BN_new();
            bnY = _openSslApiProvider.BN_new();

            err = _openSslApiProvider.EC_POINT_is_on_curve(pCurve, pPoint, IntPtr.Zero);
            if (err != 1)
                return err;

            err = _openSslApiProvider.EC_POINT_get_affine_coordinates_GFp(pCurve, pPoint, bnX, bnY, IntPtr.Zero);
            if (err != 1)
            {
                _openSslApiProvider.BN_free(bnX);
                _openSslApiProvider.BN_free(bnY);
                return err;
            }

            err = _openSslApiProvider.BN_bn2bin(bnX, pPointX);

            var pPointXPad = new byte[GfLen + 1];
            Array.Copy(pPointX, 0, pPointXPad, 1, GfLen);
            pPointX = pPointXPad;

            if (_openSslApiProvider.BN_is_odd(bnY))
                pFlag = 1;
            else
                pFlag = 0;

            _openSslApiProvider.BN_free(bnX);
            _openSslApiProvider.BN_free(bnY);

            return 1;
        }

        public int EC_POINT2binBEUncompressed(IntPtr pCurve, IntPtr pPoint, out byte[] p_Point)
        {
            var p_PointX = new byte[GfLen];
            var p_PointY = new byte[GfLen];
            p_Point = new byte[GfLen * 2];

            var err = 1;

            IntPtr bn_X, bn_Y;

            bn_X = _openSslApiProvider.BN_new();
            bn_Y = _openSslApiProvider.BN_new();

            err = _openSslApiProvider.EC_POINT_is_on_curve(pCurve, pPoint, IntPtr.Zero);
            if (err != 1)
                return err;

            err = _openSslApiProvider.EC_POINT_get_affine_coordinates_GFp(pCurve, pPoint, bn_X, bn_Y, IntPtr.Zero);
            if (err != 1)
            {
                _openSslApiProvider.BN_free(bn_X);
                _openSslApiProvider.BN_free(bn_Y);
                return err;
            }

            err = _openSslApiProvider.BN_bn2bin(bn_X, p_PointX);
            err = _openSslApiProvider.BN_bn2bin(bn_Y, p_PointY);

            Array.Copy(p_PointX.Reverse().ToArray(), 0, p_Point, 0, GfLen);
            Array.Copy(p_PointY.Reverse().ToArray(), 0, p_Point, GfLen, GfLen);

            _openSslApiProvider.BN_free(bn_X);
            _openSslApiProvider.BN_free(bn_Y);

            return 1;
        }

        public bool VerifyEqualityOfDlOpenSsl(byte[] pW, byte[] p_U1, byte[] p_U2, byte[] p_G1, byte[] p_Y1, byte[] p_G2, byte[] p_Y2)
        {
            var err = 1;
            var pCurve = IntPtr.Zero;
            var pbnW = IntPtr.Zero;
            IntPtr pU1 = IntPtr.Zero, pU2 = IntPtr.Zero, pG1 = IntPtr.Zero, pY1 = IntPtr.Zero, pG2 = IntPtr.Zero, pY2 = IntPtr.Zero;


            pCurve = create_curve();

            if (pCurve == IntPtr.Zero)
            {
                err = 0;
                goto exit;
            }

            pU1 = _openSslApiProvider.EC_POINT_new(pCurve);
            pU2 = _openSslApiProvider.EC_POINT_new(pCurve);
            pG1 = _openSslApiProvider.EC_POINT_new(pCurve);
            pY1 = _openSslApiProvider.EC_POINT_new(pCurve);
            pG2 = _openSslApiProvider.EC_POINT_new(pCurve);
            pY2 = _openSslApiProvider.EC_POINT_new(pCurve);

            CreateEcPoint(pCurve, p_U1, pU1);
            CreateEcPoint(pCurve, p_U2, pU2);
            CreateEcPoint(pCurve, p_G1, pG1);
            CreateEcPoint(pCurve, p_Y1, pY1);
            CreateEcPoint(pCurve, p_G2, pG2);
            CreateEcPoint(pCurve, p_Y2, pY2);

            pbnW = _openSslApiProvider.BN_new();
            _openSslApiProvider.BN_bin2bn(pW, GfLen, pbnW);

            var pData2Hash = new byte[2 * 6 * (GfLen + 1)];
            var pHash = new byte[GfLen];

            Array.Copy(p_U1, pData2Hash, GfLen + 1);

            Array.Copy(p_U2, 0, pData2Hash, GfLen + 1, GfLen + 1);

            Array.Copy(p_G1, 0, pData2Hash, 2 * (GfLen + 1), GfLen + 1);

            Array.Copy(p_Y1, 0, pData2Hash, 3 * (GfLen + 1), GfLen + 1);

            Array.Copy(p_G2, 0, pData2Hash, 4 * (GfLen + 1), GfLen + 1);

            Array.Copy(p_Y2, 0, pData2Hash, 5 * (GfLen + 1), GfLen + 1);

            // toLower(p_Data2Hash, (GF_LEN + 1) * 2 * 6);
            var hex = BitConverter.ToString(pData2Hash).Replace("-", string.Empty).ToLower();

            pData2Hash = hex.HexToByteArray();

            if (!HashCompresedPointsBe(pData2Hash, 6, out pHash))
                goto exit;

            err = VerifyEqualityOfDl(pCurve, pbnW, pHash, pU1, pU2, pG1, pY1, pG2, pY2);

            exit:
            _openSslApiProvider.BN_free(pbnW);
            _openSslApiProvider.EC_POINT_free(pU1);
            _openSslApiProvider.EC_POINT_free(pU2);
            _openSslApiProvider.EC_POINT_free(pG1);
            _openSslApiProvider.EC_POINT_free(pY1);
            _openSslApiProvider.EC_POINT_free(pG2);
            _openSslApiProvider.EC_POINT_free(pY2);

            _openSslApiProvider.EC_GROUP_free(pCurve);
            if (err == 1)
            {
                return true;
            }

            return false;
        }

        public int CreateEcPoint(IntPtr pCurve, byte[] compressed, IntPtr result)
        {
            var err = 1;
            var flag = GetFlag(compressed);

            if (flag == 0 || flag == 1)
            {
                var x = new byte[GfLen];
                for (var i = 0; i < GfLen; i++)
                {
                    x[i] = compressed[i + 1];
                }
                err = binBE2EC_POINTCompressed(pCurve, x, flag, result);
            }
            else if (flag == 2)
            {
                var x = new byte[GfLen];
                var y = new byte[GfLen];
                for (var i = 0; i < GfLen; i++)
                {
                    x[i] = compressed[i + 1];
                }
                for (var i = 0; i < GfLen; i++)
                {
                    y[i] = compressed[i + GfLen + 1];
                }
                err = binBE2EC_POINTUncompressed(pCurve, x, y, result);
            }
            else
            {
                err = 0;
            }

            return err;
        }

        public byte GetFlag(byte[] p)
        {
            if (p[0] == 0x02)
            {
                return 0;
            }

            if (p[0] == 0x03)
            {
                return 1;
            }

            if (p[0] == 0x04)
            {
                return 2;
            }

            throw new ArgumentException("Invalid compressed point");
        }


        public bool HashCompresedPointsBe(byte[] pCompressedPoints, int uiNumOfPoints, out byte[] pHash)
        {
            var pPoints2Hash = new byte[uiNumOfPoints * (GfLen + 1)];
            var pPoints2HashHex = new byte[uiNumOfPoints * 2 * (GfLen + 1)];

            var gost2012Hasher = new Gost3411_2012_256CryptoServiceProvider(_cryptoApiProvider);

            //gost2012Hasher.Initialize();

            Array.Copy(pCompressedPoints, pPoints2Hash, uiNumOfPoints * (GfLen + 1));

            pPoints2HashHex = ToHex(pPoints2Hash);

            pHash = gost2012Hasher.ComputeHash(pPoints2HashHex);

            //pHash = gost2012Hasher.Hash;

            return pHash != null;
        }

        public byte[] ToHex(byte[] input)
        {
            var output = new byte[input.Length * 2];
            var hex = "0123456789abcdef".ToCharArray();
            var outputIndex = 0;

            for (var i = 0; i < input.Length; i++)
            {
                output[outputIndex++] = (byte)hex[(input[i] >> 4) & 0xF];
                output[outputIndex++] = (byte)hex[input[i] & 0xF];

                if (outputIndex + 2 - output.Length > 0)
                {
                    // Truncate output string if it would overflow the buffer
                    break;
                }
            }
            return output;
        }

        public int VerifyEqualityOfDl(IntPtr pCurve, IntPtr pbnW, byte[] pHash, IntPtr pU1, IntPtr pU2, IntPtr pG1, IntPtr pY1, IntPtr pG2, IntPtr pY2)
        {
            var err = 1;
            IntPtr ctx;
            IntPtr pbnQ, pbnHash;
            IntPtr pwG, phashY, phashYplusU;

            pbnQ = _openSslApiProvider.BN_new();
            pbnHash = _openSslApiProvider.BN_new();

            ctx = _openSslApiProvider.BN_CTX_new();

            pwG = _openSslApiProvider.EC_POINT_new(pCurve);
            phashY = _openSslApiProvider.EC_POINT_new(pCurve);
            phashYplusU = _openSslApiProvider.EC_POINT_new(pCurve);

            err = _openSslApiProvider.EC_GROUP_get_order(pCurve, pbnQ, ctx);
            if (err != 1)
                goto exit;


            _openSslApiProvider.BN_bin2bn(pHash, GfLen, pbnHash);

            // First, check that w*G1 == hash*Y1 + U1:

            // w*G1:
            err = _openSslApiProvider.EC_POINT_mul(pCurve, pwG, IntPtr.Zero, pG1, pbnW, ctx);
            if (err != 1)
                goto exit;

            // hash*Y1:
            err = _openSslApiProvider.EC_POINT_mul(pCurve, phashY, IntPtr.Zero, pY1, pbnHash, ctx);
            if (err != 1)
                goto exit;

            // hash*Y1 + U1:
            err = _openSslApiProvider.EC_POINT_add(pCurve, phashYplusU, phashY, pU1, ctx);
            if (err != 1)
                goto exit;

            err = _openSslApiProvider.EC_POINT_cmp(pCurve, pwG, phashYplusU, ctx);
            if (err != 0) // points are not equal
            {
                err = 0;
                goto exit;
            }

            // Second, check that w*G2 == hash*Y2 + U2:

            // w*G2:
            err = _openSslApiProvider.EC_POINT_mul(pCurve, pwG, IntPtr.Zero, pG2, pbnW, ctx);
            if (err != 1)
                goto exit;

            // hash*Y2:
            err = _openSslApiProvider.EC_POINT_mul(pCurve, phashY, IntPtr.Zero, pY2, pbnHash, ctx);
            if (err != 1)
                goto exit;

            // hash*Y2 + U2:
            err = _openSslApiProvider.EC_POINT_add(pCurve, phashYplusU, phashY, pU2, ctx);
            if (err != 1)
                goto exit;

            err = _openSslApiProvider.EC_POINT_cmp(pCurve, pwG, phashYplusU, ctx);
            if (err != 0) // points are not equal
            {
                err = 0;
                goto exit;
            }


            err = 1; // Ok

            exit:

            _openSslApiProvider.EC_POINT_free(pwG);
            _openSslApiProvider.EC_POINT_free(phashY);
            _openSslApiProvider.EC_POINT_free(phashYplusU);

            _openSslApiProvider.BN_free(pbnHash);
            _openSslApiProvider.BN_free(pbnQ);
            _openSslApiProvider.BN_CTX_free(ctx);

            return err;
        }

        public byte[] GetBytes(Tx tx, byte[] senderPublicKey)
        {
            var feeAssetId = !string.IsNullOrEmpty(tx.FeeAssetId) ? Encoding.UTF8.GetBytes(tx.FeeAssetId) : new byte[] { 0 };
            var atomicBadge = new byte[] { 0 };
            var fee = LongToBytes(0);

            var timestamp = LongToBytes(tx.Ts).Skip(2).ToArray();
            var rawLength = IntToBytes(tx.Raw.Length).Skip(2);
            var paramsBytes = rawLength.Concat(GetParamsBytes(tx.Raw)).ToArray();

            byte[] bytes;
            List<byte> data;
            switch (tx.Type)
            {
                case 103:
                    var image = new List<byte>();
                    var imageBytes = Encoding.UTF8.GetBytes(tx.Extra.Image!);
                    image.Add(0);
                    image.Add((byte)imageBytes.Length);
                    image.AddRange(imageBytes);

                    var imageHash = new List<byte>();
                    var imageHashBytes = Encoding.UTF8.GetBytes(tx.Extra.ImageHash!);
                    imageHash.Add(0);
                    imageHash.Add((byte)imageHashBytes.Length);
                    imageHash.AddRange(imageHashBytes);

                    var contractName = new List<byte>();
                    var contractNameBytes = Encoding.UTF8.GetBytes(tx.Extra.ContractName!);
                    imageHash.Add(0);
                    imageHash.Add((byte)contractNameBytes.Length);
                    imageHash.AddRange(contractNameBytes);

                    data = new List<byte> { 103 };
                    data.Add((byte)tx.Version);
                    data.AddRange(senderPublicKey);
                    data.AddRange(image);
                    data.AddRange(imageHash);
                    data.AddRange(contractName);
                    data.AddRange(paramsBytes);
                    data.AddRange(new byte[] { 0, 0 });
                    data.AddRange(fee);
                    data.AddRange(timestamp);
                    if (tx.Version >= 2)
                    {
                        data.AddRange(feeAssetId);
                    }

                    if (tx.Version >= 3)
                    {
                        data.AddRange(atomicBadge);
                    }

                    data.AddRange(new byte[] { 0 });
                    data.AddRange(new byte[] { 0 });
                    data.Add(1);
                    data.Add(0);
                    data.Add(2);
                    bytes = data.ToArray();
                    break;
                case 104:
                    var contractId = new List<byte>();
                    contractId.Add(0);
                    var decoded = Base58.Bitcoin.Decode(tx.ContractId);
                    contractId.Add((byte)decoded.Length);
                    contractId.AddRange(Base58.Bitcoin.Decode(tx.ContractId));
                    var contractVersion = IntToBytes(tx.Extra.ContractVersion!.Value);
                    data = new List<byte>
                    {
                        104
                    };
                    data.Add((byte)tx.Version);
                    data.AddRange(senderPublicKey);
                    data.AddRange(contractId);
                    data.AddRange(paramsBytes);
                    data.AddRange(new byte[] { 0, 0 });
                    data.AddRange(fee);
                    data.AddRange(timestamp);
                    data.AddRange(contractVersion);
                    if (tx.Version >= 3)
                    {
                        data.AddRange(feeAssetId);
                    }

                    if (tx.Version >= 4)
                    {
                        data.AddRange(atomicBadge);
                    }

                    bytes = data.ToArray();
                    break;
                default:
                    bytes = Array.Empty<byte>();
                    break;
            }

            return bytes;
        }

        private byte[] GetParamsBytes(JsonModel[] raw)
        {
            var bytes = new List<byte>();
            foreach (var model in raw)
            {
                var valBytes = new List<byte>();
                if (model.BoolValue != null)
                {
                    valBytes.Add(1);
                    valBytes.AddRange(BitConverter.GetBytes(model.BoolValue.Value ? 1 : 0));
                }
                else if (model.IntValue != null)
                {
                    valBytes.Add(0);
                    valBytes.AddRange(LongToBytes(model.IntValue.Value));
                }
                else if (model.BinaryValue != null)
                {
                    var binaryData = Convert.FromBase64String(model.BinaryValue);
                    var binLen = IntToBytes(binaryData.Length);
                    valBytes.Add(2);
                    valBytes.AddRange(binLen);
                    valBytes.AddRange(binaryData);
                }
                else if (!string.IsNullOrEmpty(model.StringValue))
                {
                    var stringData = Encoding.UTF8.GetBytes(model.StringValue);
                    var strLen = IntToBytes(stringData.Length);
                    valBytes.Add(3);
                    valBytes.AddRange(strLen);
                    valBytes.AddRange(stringData);
                }

                var result = new List<byte>();
                result.Add(0);
                var keyBytes = Encoding.UTF8.GetBytes(model.Key);
                result.Add((byte)keyBytes.Length);
                result.AddRange(keyBytes);
                result.AddRange(valBytes);

                bytes.AddRange(result);
            }

            return bytes.ToArray();
        }

        private byte[] IntToBytes(int x)
        {
            var byteArray = BitConverter.GetBytes(x);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(byteArray);
            }
            return byteArray;
        }

        private byte[] LongToBytes(long input)
        {
            var byteArray = BitConverter.GetBytes(input);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(byteArray);
            }
            return byteArray;
        }

        public int GetTotalTxCountOld(string directory)
        {
            var command = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "cat *.csv | wc -l" : @"/c ""type *.csv | find /c /v """"""";
            var tool = RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "bash" : "cmd.exe";
            var startInfo = new ProcessStartInfo
            {
                WorkingDirectory = directory,
                WindowStyle = ProcessWindowStyle.Hidden,
                FileName = tool,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                Arguments = command
            };

            var proc = Process.Start(startInfo);
            var strOutput = proc?.StandardOutput.ReadToEnd();
            proc?.WaitForExit();
            proc?.Kill();

            return int.Parse(strOutput);
        }

        public int GetTotalTxCount(string directory)
        {
            var searchPattern = "*.csv";
            var files = Directory.GetFiles(directory, searchPattern);

            var totalLines = files.Select(file =>
            {
                using (var reader = File.OpenText(file))
                {
                    return File.ReadLines(file).Count();
                }
            }).Sum();

            return totalLines;
        }

        public bool ValidateBlindSignature(Dictionary<string, object> contractState, Tx tx)
        {
            var votingBase = (VotingBaseKeyModel)contractState["VOTING_BASE"];
            var blindSigType = votingBase.BlindSigType;

            if (blindSigType == "TeZhu")
            {
                return ValidateBlindSignatureTeZhu(votingBase, tx);
            }

            if (blindSigType == "RSA")
            {
                return ValidateBlindSignatureRsa(votingBase, tx);
            }
            //for old test data

            return ValidateBlindSignatureRsa(votingBase, tx);
        }

        public bool ValidateBlindSignatureTeZhu(VotingBaseKeyModel votingBase, Tx tx)
        {
            var blindSigParams = votingBase.BlindSigParams![0]!.PadLeft(260, '0');

            var signature = new byte[128];
            var signatureRaw = Convert.FromBase64String(tx.Params["blindSig"] as string);
            var copyOffset = 128 - signatureRaw.Length;
            Buffer.BlockCopy(signatureRaw, 0, signature, copyOffset, signatureRaw.Length);

            var publicKey = HexToByteArray(blindSigParams);
            var message = Encoding.UTF8.GetBytes(tx.SenderPublicKey);

            return VerifySignatureTeZhu(publicKey, signature, message);
        }

        private bool VerifySignatureTeZhu(byte[] publicKey, byte[] signature, byte[] message)
        {
            var err = 1;
            var validationHelper = new ValidationHelper();

            var curve = create_curve();
            var ctx = _openSslApiProvider.BN_CTX_new();

            var g = validationHelper.CreatePoint(curve, CryptoProHelper.Base);

            var key = new PublicKey(publicKey, this, _openSslApiProvider);
            var sign = new Signature(signature, _openSslApiProvider);

            //G * T
            var gmulT = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_mul(curve, gmulT, IntPtr.Zero, g, sign.T, ctx);

            //Z * Y 
            var zmulY = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_mul(curve, zmulY, IntPtr.Zero, key.Z, sign.Y, ctx);

            //C = (G * T) + (Z * Y)
            var c = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_add(curve, c, gmulT, zmulY, ctx);


            //G * S
            var gmulS = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_mul(curve, gmulS, IntPtr.Zero, g, sign.S, ctx);

            //Q * Y 
            var qmulY = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_mul(curve, qmulY, IntPtr.Zero, key.Q, sign.Y, ctx);

            //(Q * Y) * C
            var qmulYmulC = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_mul(curve, qmulYmulC, IntPtr.Zero, qmulY, sign.C, ctx);

            //-((Q * Y) * C)
            _openSslApiProvider.EC_POINT_invert(curve, qmulYmulC, ctx);

            //A = (G * S) + -((Q * Y) * C)          
            var a = _openSslApiProvider.EC_POINT_new(curve);
            _openSslApiProvider.EC_POINT_add(curve, a, gmulS, qmulYmulC, ctx);

            var aBe = new byte[CryptoProHelper.GfLen];

            err = EC_POINT2binBEUncompressed(curve, a, out aBe);
            if (err != 1)
                return false;

            var aLeX = aBe.Take(CryptoProHelper.GfLen).ToArray();
            var aLeY = aBe.Skip(CryptoProHelper.GfLen).Take(CryptoProHelper.GfLen).ToArray().RemoveLeadingZeros();

            var aLe = new byte[CryptoProHelper.GfLen * 2];
            Array.Copy(aLeX, 0, aLe, 0, aLeX.Length);
            Array.Copy(aLeY, 0, aLe, CryptoProHelper.GfLen, aLeY.Length);


            var cBe = new byte[CryptoProHelper.GfLen];

            err = EC_POINT2binBEUncompressed(curve, c, out cBe);
            if (err != 1)
                return false;

            var cLeX = cBe.Take(CryptoProHelper.GfLen).ToArray();
            var cLeY = cBe.Skip(CryptoProHelper.GfLen).Take(CryptoProHelper.GfLen).ToArray().RemoveLeadingZeros();


            var cLe = new byte[CryptoProHelper.GfLen * 2];
            Array.Copy(cLeX, 0, cLe, 0, cLeX.Length);
            Array.Copy(cLeY, 0, cLe, CryptoProHelper.GfLen, cLeY.Length);

            var m = new byte[aLe.Length + cLe.Length + message.Length];

            Array.Copy(aLe, 0, m, 0, aLe.Length);
            Array.Copy(cLe, 0, m, aLe.Length, cLe.Length);
            Array.Copy(message, 0, m, aLe.Length + cLe.Length, message.Length);

            var degHash = new DegHash(_cryptoApiProvider);

            var hash = degHash.Hash(m);

            var bnHash = new BigInteger(hash);
            var bnQ = new BigInteger(OrderBin);
            var bnCp = bnHash % bnQ;
            var bnCpHex = bnCp.ToHexString();
            var res = new byte[CryptoProHelper.GfLen];
            _openSslApiProvider.BN_bn2bin(sign.C, res);
            var resHex = Convert.ToHexString(res).RemoveLeadingZeros();


            _openSslApiProvider.EC_POINT_free(a);
            _openSslApiProvider.EC_POINT_free(qmulYmulC);
            _openSslApiProvider.EC_POINT_free(qmulY);
            _openSslApiProvider.EC_POINT_free(gmulS);
            _openSslApiProvider.EC_POINT_free(c);
            _openSslApiProvider.EC_POINT_free(zmulY);
            _openSslApiProvider.EC_POINT_free(gmulT);
            _openSslApiProvider.EC_POINT_free(g);
            _openSslApiProvider.EC_GROUP_free(curve);
            _openSslApiProvider.BN_CTX_free(ctx);

            if (bnCpHex == resHex)
                return true;

            return false;
        }

        private bool ValidateBlindSignatureRsa(VotingBaseKeyModel votingBase, Tx tx)
        {
            var modulo = new BigInteger(votingBase.BlindSigModulo!, 16);
            var exp = new BigInteger(votingBase.BlindSigExponent!, 16);
            var signature = Convert.FromBase64String(tx.Params["blindSig"] as string);
            var message = Encoding.UTF8.GetBytes(tx.SenderPublicKey);
            return VerifySignature(modulo, exp, message, signature);
        }

        private bool VerifySignature(BigInteger n, BigInteger e, byte[] message, byte[] signature)
        {
            var padded = Fdh(message, n.GetBytes(), 4096);
            var data = new BigInteger(signature);
            var m1 = data.ModPow(e, n);

            return new BigInteger(padded) == m1;
        }

        private byte[] Fdh(byte[] message, byte[] n, int bitCount)
        {
            if (bitCount % 256 != 0)
            {
                throw new Exception("Wrong bit count!!!");
            }

            if (n[0] % 0x80 == 0)
            {
                throw new Exception("significant bit must be 1");
            }

            var hashes = new List<byte>();

            var iv = 0;
            var blockCount = bitCount / 256;
            var firstBlock = new BigInteger(n.Take(32).ToArray());
            var hasher = new Gost3411_2012_256CryptoServiceProvider(_cryptoApiProvider);

            while (true)
            {
                var bytes = message.Concat(n).Concat(new byte[] { 1, (byte)iv }).ToArray();
                var hashedMessage = hasher.ComputeHash(bytes);
                iv++;

                if (firstBlock >= (new BigInteger(hashedMessage)))
                {
                    hashes.AddRange(hashedMessage);
                    break;
                }
            }

            for (var i = 0; i < blockCount - 1; i++)
            {
                var bytes = message.Concat(n).Concat(new byte[] { 0, (byte)(iv + i) }).ToArray();
                var hashedMessage = hasher.ComputeHash(bytes);
                hashes.AddRange(hashedMessage);
            }

            return hashes.ToArray();
        }

        public bool IsOdd(byte[] point)
        {
            return point[0] != 0x02;
        }

        public byte[] GetX(byte[] point)
        {
            return point.Skip(1).ToArray();
        }

        public byte[] HexToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Invalid hex string");

            var bytes = new byte[hex.Length / 2];

            for (var i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        public AbBytes[][] GetAbBytes(Bulletin b)
        {
            var abBytesList = new List<AbBytes[]>();

            b.Questions.ForEach(q =>
            {
                var abBytesQuestion = new List<AbBytes>();
                q.Options.ForEach(r =>
                {
                    abBytesQuestion.Add(new AbBytes { A = r.A, B = r.B });
                });
                abBytesList.Add(abBytesQuestion.ToArray());
            });

            return abBytesList.ToArray();
        }
    }
}
