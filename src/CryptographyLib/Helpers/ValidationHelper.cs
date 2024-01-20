using CryptographyLib.Helpers.CryptoApi;
using CryptographyLib.Helpers.Extensions;
using CryptographyLib.Helpers.OpenSslApi;
using CryptographyLib.Models;
using SimpleBase;
using System.Text;

namespace CryptographyLib.Helpers
{
    public class ValidationHelper
    {
        private CryptoApiProvider _cryptoApiProvider;
        private CryptoProHelper _cryptoProHelper;
        private OpenSslApiProvider _openSslApiProvider;

        public ValidationHelper()
        {
            _cryptoApiProvider = new CryptoApiProvider();
            _cryptoProHelper = new CryptoProHelper();
            _openSslApiProvider = new OpenSslApiProvider();
        }

        public List<List<int?>> CalculateResults(AbBytes[][] sums, List<int> dimension, int n, byte[] masterPublicKey, Decryption[][] masterDecryption,
            byte[] commissionPublicKey, Decryption[][] commissionDecryption)
        {
            var pCurve = _cryptoProHelper.create_curve();
            var ctx = IntPtr.Zero;

            var p1 = masterPublicKey;
            var p2 = commissionPublicKey;

            var hash1 = HashPoints(new List<byte[]> { p1, p2 });
            var hash2 = HashPoints(new List<byte[]> { p2, p1 });

            var encryptedSums = new List<List<byte[]>>();

            if (dimension.Count > 2)
            {
                for (var i = 0; i < dimension[0]; i++)
                {
                    for (var qIdx = 0; qIdx < dimension[1]; qIdx++)
                    {
                        var qs = new List<byte[]>();
                        for (var oIdx = 0; oIdx < dimension[2]; oIdx++)
                        {
                            var h1 = _openSslApiProvider.BN_new();
                            var h2 = _openSslApiProvider.BN_new();

                            if (IntPtr.Zero == (h1 = _openSslApiProvider.BN_bin2bn(hash1, hash1.Length, IntPtr.Zero))) throw new Exception();
                            if (IntPtr.Zero == (h2 = _openSslApiProvider.BN_bin2bn(hash2, hash2.Length, IntPtr.Zero))) throw new Exception();

                            var point1 = CreatePoint(pCurve, masterDecryption[qIdx][oIdx].P);
                            var P1 = _openSslApiProvider.EC_POINT_new(pCurve);
                            _openSslApiProvider.EC_POINT_mul(pCurve, P1, IntPtr.Zero, point1, h1, ctx);

                            var point2 = CreatePoint(pCurve, commissionDecryption[qIdx][oIdx].P);
                            var P2 = _openSslApiProvider.EC_POINT_new(pCurve);
                            _openSslApiProvider.EC_POINT_mul(pCurve, P2, IntPtr.Zero, point2, h2, ctx);

                            var C = _openSslApiProvider.EC_POINT_new(pCurve);
                            _openSslApiProvider.EC_POINT_add(pCurve, C, P1, P2, ctx);

                            var pointToCompare = CreatePoint(pCurve, sums[qIdx][oIdx].B);

                            if (_openSslApiProvider.EC_POINT_cmp(pCurve, C, pointToCompare, ctx) == 0)
                            {

                            }
                            else
                            {
                                _openSslApiProvider.EC_POINT_invert(pCurve, C, ctx);

                                _openSslApiProvider.EC_POINT_add(pCurve, C, pointToCompare, C, ctx);

                                var p_PointX = new byte[CryptoProHelper.GfLen];
                                byte flag = 0;

                                _cryptoProHelper.EC_POINT2binBECompressed(pCurve, C, out p_PointX, out flag);

                                if (flag == 0)
                                {
                                    p_PointX[0] = 0x02;
                                }
                                else
                                {
                                    p_PointX[0] = 0x03;
                                }

                                qs.Add(p_PointX);
                            }
                        }
                        encryptedSums.Add(qs);
                    }
                }
            }

            var Qs = new List<byte[]>();

            foreach (var qs in encryptedSums)
            {
                for (var i = 0; i < qs.Count; i++)
                {
                    var qToCompare = qs[i];
                    var isUnique = true;

                    for (var j = i + 1; j < qs.Count; j++)
                    {
                        if (qToCompare.SequenceEqual(qs[j]))
                        {
                            isUnique = false;
                            break;
                        }
                    }

                    if (isUnique)
                    {
                        Qs.Add(qToCompare);
                    }
                }
            }

            var decryptedQs = SolveDlp(Qs, n);

            return encryptedSums.Select(options =>
                options.Select(sum =>
                {
                    if (sum.Length == 0)
                    {
                        return null;
                    }

                    var key = sum;
                    return decryptedQs.Find(Q => key == Q.Key)?.Sum;
                }).ToList()
            ).ToList();
        }

        public List<DLPResult> SolveDlp(List<byte[]> points, int total)
        {
            var result = new int[points.Count];

            var err = 1;
            var pCurve = IntPtr.Zero;
            var ctx = IntPtr.Zero;
            var Points = new IntPtr[points.Count];
            IntPtr pBase = IntPtr.Zero, pCursor = IntPtr.Zero;
            byte flag = 0;
            var x = new byte[32];
            IntPtr xBase = IntPtr.Zero, yBase = IntPtr.Zero;

            ctx = _openSslApiProvider.BN_CTX_new();

            pCurve = _cryptoProHelper.create_curve();
            if (IntPtr.Zero == pCurve)
            {
                err = 0;
                goto exit;
            }

            pCursor = _openSslApiProvider.EC_POINT_new(pCurve);
            pBase = _openSslApiProvider.EC_POINT_new(pCurve);

            for (var i = 0; i < points.Count; i++)
            {
                Points[i] = _openSslApiProvider.EC_POINT_new(pCurve);

                for (var j = 0; j < CryptoProHelper.GfLen; j++)
                {
                    x[j] = points[i][j + 1];
                }

                if (points[i][0] == 0x02)
                {
                    flag = 0;
                }
                else if (points[i][0] == 0x03)
                {
                    flag = 1;
                }

                err = _cryptoProHelper.binBE2EC_POINTCompressed(pCurve, x, flag, Points[i]);
                if (err != 1)
                    goto exit;

            }

            xBase = _openSslApiProvider.BN_bin2bn(_cryptoProHelper.XBin, _cryptoProHelper.XBin.Length, IntPtr.Zero);
            yBase = _openSslApiProvider.BN_bin2bn(_cryptoProHelper.YBin, _cryptoProHelper.YBin.Length, IntPtr.Zero);

            err = _openSslApiProvider.EC_POINT_set_affine_coordinates_GFp(pCurve, pBase, xBase, yBase, IntPtr.Zero);
            if (err != 1)
            {
                goto exit;
            }

            err = _openSslApiProvider.EC_POINT_copy(pCursor, pBase);
            if (err != 1)
                goto exit;

            for (var i = 0; i < total; i++)
            {
                for (var j = 0; j < points.Count; j++)
                {
                    if (_openSslApiProvider.EC_POINT_cmp(pCurve, pCursor, Points[j], ctx) == 0)
                    {
                        result[j] = i + 1;
                    }
                }
                _openSslApiProvider.EC_POINT_add(pCurve, pCursor, pCursor, pBase, ctx);
            }

            exit:

            for (var i = 0; i < points.Count; i++)
            {
                _openSslApiProvider.EC_POINT_free(Points[i]);
            }
            _openSslApiProvider.EC_POINT_free(pCursor);
            _openSslApiProvider.EC_POINT_free(pBase);

            _openSslApiProvider.EC_GROUP_free(pCurve);

            _openSslApiProvider.BN_free(xBase);
            _openSslApiProvider.BN_free(yBase);

            _openSslApiProvider.BN_CTX_free(ctx);

            var dlpResults = new List<DLPResult>();

            for (var i = 0; i < points.Count; i++)
            {
                dlpResults.Add(new DLPResult
                {
                    Key = points[i],
                    Sum = result[i]
                });
            }

            return dlpResults;
        }

        public byte[] HashPoints(List<byte[]> points)
        {
            var pointsCompressed = new List<string>();

            foreach (var point in points)
            {
                pointsCompressed.Add(BitConverter.ToString(point).Replace("-", "").ToLower());
            }

            var source = string.Join("", pointsCompressed);

            var hex = HexToAscii(source);

            var sb = new StringBuilder();

            foreach (var b in hex)
            {
                sb.Append(b.ToString());
            }

            var hexString = Convert.FromHexString(sb.ToString());

            hex = hexString;

            var gost3411 = new Gost3411_2012_256CryptoServiceProvider(_cryptoApiProvider);

            var hash = gost3411.ComputeHash(hex);

            return hash;
        }

        public byte[] HexToAscii(string hex)
        {
            var result = new List<byte>();

            for (var i = 0; i < hex.Length; i += 1)
            {
                var ch = hex.Substring(i, 1)[0];
                var asciiCode = (int)ch;
                var asciiCodeHex = Convert.ToByte(Convert.ToString(asciiCode, 16));

                result.Add(asciiCodeHex);
            }

            return result.ToArray();
        }

        public IntPtr CreatePoint(IntPtr pCurve, byte[] point)
        {
            var pPoint = _openSslApiProvider.EC_POINT_new(pCurve);

            _cryptoProHelper.CreateEcPoint(pCurve, point, pPoint);

            if (pPoint == IntPtr.Zero)
                throw new Exception("pPoint = IntPtr.Zero CreatePoint");

            return pPoint;
        }

        public IntPtr CreatePoint(IntPtr pCurve, string pointHex)
        {
            return CreatePoint(pCurve, pointHex.HexToByteArray());
        }

        public bool ValidateDecryption(AbBytes[][] sums, List<int> dimension, byte[] publicKey, Decryption[][] decryption)
        {
            for (var qIdx = 0; qIdx < decryption.Length; qIdx++)
            {
                for (var oIdx = 0; oIdx < decryption[qIdx].Length; oIdx++)
                {
                    var decr = decryption[qIdx][oIdx];
                    if (!ValidateDlEq(decr.W.HexToByteArray(), decr.U1.HexToByteArray(), decr.U2.HexToByteArray(),
                        CryptoProHelper.BaseCompressed.HexToByteArray(), publicKey, sums[qIdx][oIdx].A, decr.P.HexToByteArray()))
                        throw new Exception("Расшифровка некорректна.");
                }
            }

            return true;
        }

        public bool ValidateDlEq(byte[] w, byte[] u1, byte[] u2, byte[] g1, byte[] y1, byte[] g2, byte[] y2)
        {
            return _cryptoProHelper.VerifyEqualityOfDlOpenSsl(w, u1, u2, g1, y1, g2, y2);
        }


        public Task<bool> ValidateTxSignature(Tx tx)
        {
            var senderPublicKey = Base58.Bitcoin.Decode(tx.SenderPublicKey);
            var signature = Base58.Bitcoin.Decode(tx.Signature);
            var data = _cryptoProHelper.GetBytes(tx, senderPublicKey); //сообщение M

            Array.Reverse(signature);

            try
            {
                var hasher = new Stribog();
                var hashedMessage = hasher.ComputeHash(data);

                var publicKeyProvider = new Gost3410_2012_256CryptoServiceProvider(_cryptoApiProvider);
                var pPubKeyBlobPref = new byte[] {
                                    0x06, 0x20, 0x00, 0x00, 0x49, 0x2E, 0x00, 0x00, 0x4D, 0x41,
                                    0x47, 0x31, 0x00, 0x02, 0x00, 0x00, 0x30, 0x0B, 0x06, 0x09,
                                    0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02 };

                var pPubKeyBlob = pPubKeyBlobPref.Concat(senderPublicKey).ToArray();

                var isValid = publicKeyProvider.VerifySignature(pPubKeyBlob, data, signature);

                return Task.FromResult(isValid);
            }
            catch (Exception)
            {
                return Task.FromResult(false);
            }
        }

        public Task<AbBytes[][]> AddVotesChunk(AbBytes[][][] aBs, List<int> dimension)
        {
            var result = new AbBytes[dimension.Count][];

            for (var qIdx = 0; qIdx < dimension.Count; qIdx++)
            {
                result[qIdx] = new AbBytes[dimension[qIdx]];

                for (var oIdx = 0; oIdx < dimension[qIdx]; oIdx++)
                {
                    var abBytes = result[qIdx][oIdx];
                    if (abBytes == null)
                        abBytes = new AbBytes() { A = new byte[CryptoProHelper.GfLen + 1], B = new byte[CryptoProHelper.GfLen + 1] };

                    var @as = aBs.Select(ab => ab[qIdx][oIdx].A).ToList();

                    var a = new byte[CryptoProHelper.GfLen + 1];
                    Array.Copy(abBytes.A, a, a.Length);

                    _cryptoProHelper.PublicKeyCombine(@as, out a);

                    var bs = aBs.Select(ab => ab[qIdx][oIdx].B).ToList();

                    var b = new byte[CryptoProHelper.GfLen + 1];
                    Array.Copy(abBytes.B, b, b.Length);

                    _cryptoProHelper.PublicKeyCombine(bs, out b);

                    abBytes.A = a;
                    abBytes.B = b;

                    result[qIdx][oIdx] = abBytes;
                }

            }
            return Task.FromResult(result);
        }

        public Task<ValidateBulletinResult> ValidateBulletin(Tx vote, string mainKey, int[][] dimension)
        {
            var binary = Convert.FromBase64String(vote.Params["vote"] as string ?? throw new InvalidOperationException());

            // from worker.ts
            var bulletin = Bulletin.Decode(binary);

            if (
                bulletin.Questions.Count != dimension.Length ||
                bulletin.Questions.Any((q) => q.Options.Count != dimension[bulletin.Questions.IndexOf(q)][2])
            )
            {
                return Task.FromResult(new ValidateBulletinResult { Valid = false, TxId = vote.NestedTxId });
            }


            var publicKey = mainKey.HexToByteArray();

            var valid = bulletin.Questions.All((q) =>
            {
                return q.Options.Concat(new[] { q.Sum }).All((option) =>
                {
                    var range = dimension[bulletin.Questions.IndexOf(q)];
                    var min = range[0];
                    var max = range[1];

                    var conf = q.Options.IndexOf(option) == -1
                        ? Enumerable.Range(min, max - min + 1).ToArray()
                        : new[] { 0, 1 };

                    var messages = new int[conf.Length];
                    for (var i = 0; i < conf.Length; i++)
                    {
                        messages[i] = conf[i];
                    }

                    var A = _cryptoProHelper.GetX(option.A);
                    var B = _cryptoProHelper.GetX(option.B);

                    var As = option.As.Select(_cryptoProHelper.GetX).ToList();
                    var AsFlags = new List<byte>();
                    for (var i = 0; i < option.As.Count; i++)
                    {
                        AsFlags.Add((byte)(_cryptoProHelper.IsOdd(option.As[i]) ? 1 : 0));
                    }

                    var Bs = option.Bs.Select(_cryptoProHelper.GetX).ToList();
                    var BsFlags = new List<byte>();
                    for (var i = 0; i < option.Bs.Count; i++)
                    {
                        BsFlags.Add((byte)(_cryptoProHelper.IsOdd(option.Bs[i]) ? 1 : 0));
                    }

                    var c = option.C.Aggregate((a, b) => a.Concat(b).ToArray());
                    var r = option.R.Aggregate((a, b) => a.Concat(b).ToArray());

                    //from curve.c VerifyRangeProofExCompressedCryptoPro

                    var valid = VerifyRangeProofExCompressedCryptoPro(_cryptoProHelper.GetX(publicKey), (byte)(_cryptoProHelper.IsOdd(publicKey) ? 1 : 0),
                        messages, conf.Length, A, (byte)(_cryptoProHelper.IsOdd(option.A) ? 1 : 0), B, (byte)(_cryptoProHelper.IsOdd(option.B) ? 1 : 0),
                        As, AsFlags, Bs, BsFlags, c, r);
                    if (!valid)
                    {
                        return false;
                    }

                    return valid;

                });
            });

            return Task.FromResult(new ValidateBulletinResult { Valid = valid });
        }

        public bool VerifyRangeProofExCompressedCryptoPro(byte[] pPubKeyX, byte flagPubKey, int[] pAllMessages, int numOfMessages,
        byte[] pAx, byte flagA, byte[] pBx, byte flagB, List<byte[]> pAsx, List<byte> pFlagAs, List<byte[]> pBsx, List<byte> pFlagBs,
        byte[] pC, byte[] pRss)
        {
            var pbnQ = new BigInteger(_cryptoProHelper.OrderBin);

            var b = _cryptoApiProvider.CryptAcquireContext(out var hProv, null, null, 80, 0xF0000000);
            if (!b)
                return false;

            b = _cryptoApiProvider.CryptSetProvParam(hProv, 95, CryptoProHelper.Gost34102012256CryptoProBParamSet, 0);
            if (!b)
                return false;
            b = _cryptoApiProvider.CryptCreateHash(hProv, 32801, IntPtr.Zero, 0, out var hHash);
            if (!b)
                return false;

            var err = _cryptoProHelper.Point2HexCompressedEx(pPubKeyX, flagPubKey, out var pubKey);
            if (err != 1)
                return false;

            if (!_cryptoApiProvider.CryptHashData(hHash, Encoding.UTF8.GetBytes(pubKey), 2 + 2 * CryptoProHelper.GfLen, flagPubKey))
            {
                return false;
            }

            err = _cryptoProHelper.Point2HexCompressedEx(pAx, flagA, out pubKey);
            if (err != 1)
                return false;

            if (!_cryptoApiProvider.CryptHashData(hHash, Encoding.UTF8.GetBytes(pubKey), 2 + 2 * CryptoProHelper.GfLen, 0))
            {
                return false;
            }

            err = _cryptoProHelper.Point2HexCompressedEx(pBx, flagB, out pubKey);
            if (err != 1)
                return false;

            if (!_cryptoApiProvider.CryptHashData(hHash, Encoding.UTF8.GetBytes(pubKey), 2 + 2 * CryptoProHelper.GfLen, 0))
            {
                return false;
            }

            for (var i = 0; i < pAsx.Count; i++)
            {
                err = _cryptoProHelper.Point2HexCompressedEx(pAsx[i], pFlagAs[i], out pubKey);
                if (err != 1)
                    return false;

                if (!_cryptoApiProvider.CryptHashData(hHash, Encoding.UTF8.GetBytes(pubKey), 2 + 2 * CryptoProHelper.GfLen, 0))
                {
                    return false;
                }
            }

            for (var i = 0; i < pBsx.Count; i++)
            {
                err = _cryptoProHelper.Point2HexCompressedEx(pBsx[i], pFlagBs[i], out pubKey);
                if (err != 1)
                    return false;

                if (!_cryptoApiProvider.CryptHashData(hHash, Encoding.UTF8.GetBytes(pubKey), 2 + 2 * CryptoProHelper.GfLen, 0))
                {
                    return false;
                }
            }

            var pbnCSum = new BigInteger(0);

            for (var i = 0; i < numOfMessages; i++)
            {
                var pbnCi = new BigInteger(pC.Skip(i * CryptoProHelper.GfLen).Take(CryptoProHelper.GfLen).ToArray());

                //BN_mod_add(pbn_c_sum, pbn_c_sum, pbn_c_i, pbn_q, ctx);
                pbnCSum = (pbnCi + pbnCSum) % pbnQ;

                var a1 = _cryptoProHelper.
                    ScalarMultCompressedBe2Handle(hProv, pRss.Skip(i * CryptoProHelper.GfLen).Take(CryptoProHelper.GfLen).ToArray(),
                    null, 0, out var hKeyA1);
                if (!a1)
                    return false;

                var a2 = _cryptoProHelper.
                    ScalarMultCompressedBe2Handle(hProv, pC.Skip(i * CryptoProHelper.GfLen).Take(CryptoProHelper.GfLen).ToArray(),
                    pAx, (byte)(flagA + 2), out var hKeyA2);
                if (!a2)
                    return false;

                var asI = _cryptoProHelper.ImportPointCompressedBe(hProv, pAsx[i], (byte)(pFlagAs[i] + 2), out var hKeyAsI);
                if (!asI)
                    return false;

                var add = _cryptoProHelper.AddPointsCryptoPro(hKeyA2, hKeyAsI);
                if (!add)
                    return false;

                var equal = _cryptoProHelper.IsPubKeysEqual(hKeyA2, hKeyA1);
                if (!equal)
                    return false;
            }

            return true;
        }
    }
}
