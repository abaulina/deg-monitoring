using System.Runtime.InteropServices;

namespace CryptographyLib.Helpers.CryptoApi
{
    public class CryptoApiProvider
    {
        private PlatformID _pid;
        public CryptoApiProvider()
        {
            OperatingSystem os = Environment.OSVersion;
            _pid = os.Platform;
        }

        public bool CryptImportKey(
            IntPtr hProv,
            byte[] pbData,
            int dwDataLen,
            IntPtr hPubKey,
            int dwFlags,
            out IntPtr phKey)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptImportKey(
                       hProv,
                       pbData,
                       dwDataLen,
                       hPubKey,
                       dwFlags,
                       out phKey);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptImportKey(
                       hProv,
                       pbData,
                       dwDataLen,
                       hPubKey,
                       dwFlags,
                       out phKey);
                default:
                    throw new PlatformNotSupportedException();
            }
        }
        public bool CryptAcquireContext(
           out IntPtr hProv,
           string? pszContainer,
           string? pszProvider,
           uint dwProvType,
           uint dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptAcquireContext(
                        out hProv,
                        pszContainer,
                        pszProvider,
                        dwProvType,
                        dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptAcquireContext(
                        out hProv,
                        pszContainer,
                        pszProvider,
                        dwProvType,
                        dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptReleaseContext(
            IntPtr hProv,
            int dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptReleaseContext(
                    hProv,
                    dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptReleaseContext(
                    hProv,
                    dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }
        public bool CryptDestroyKey(
            IntPtr hKey)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptDestroyKey(
                        hKey);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptDestroyKey(
                        hKey);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptExportPublicKeyInfo(
        IntPtr hCryptProv,
        uint dwKeySpec,
        uint dwCertEncodingType,
        IntPtr pInfo,
        ref uint pcbInfo)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptExportPublicKeyInfo(
                        hCryptProv,
                        dwKeySpec,
                        dwCertEncodingType,
                        pInfo,
                        ref pcbInfo);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptExportPublicKeyInfo(
                        hCryptProv,
                        dwKeySpec,
                        dwCertEncodingType,
                        pInfo,
                        ref pcbInfo);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptSetProvParam(IntPtr hProv, int dwParam, string pbData, int dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptCreateHash(IntPtr hProv, int Algid, IntPtr hKey, int dwFlags, out IntPtr phHash)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptCreateHash(hProv, Algid, hKey, dwFlags, out phHash);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptCreateHash(hProv, Algid, hKey, dwFlags, out phHash);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptHashData(IntPtr hHash, byte[] pbData, int dwDataLen, int dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptVerifySignature(
        IntPtr hHash,
        byte[] pbSignature,
        int dwSigLen,
        IntPtr hPubKey,
        string sDescription,
        int dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptVerifySignature(
                        hHash,
                        pbSignature,
                        dwSigLen,
                        hPubKey,
                        sDescription,
                        dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptVerifySignature(
                        hHash,
                        pbSignature,
                        dwSigLen,
                        hPubKey,
                        sDescription,
                        dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptDestroyHash(IntPtr hHash)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptDestroyHash(hHash);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptDestroyHash(hHash);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptGetKeyParam(
          IntPtr hKey,
          int dwParam,
          ref IntPtr pbData,
          ref int pdwDataLen,
          int dwFlags
        )
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptGetKeyParam(
                        hKey,
                        dwParam,
                        ref pbData,
                        ref pdwDataLen,
                        dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptGetKeyParam(
                        hKey,
                        dwParam,
                        ref pbData,
                        ref pdwDataLen,
                        dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public unsafe bool CryptSetKeyParam(
            IntPtr hKey,
            uint dwParam,
            CRYPT_DATA_BLOB* pbData,
            int dwFlags
        )
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptSetKeyParam(
                        hKey,
                        dwParam,
                        pbData,
                        dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptSetKeyParam(
                        hKey,
                        dwParam,
                        pbData,
                        dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptExportKey(
            IntPtr hKey,
            IntPtr hExpKey,
            int dwBlobType,
            int dwFlags,
            byte[] pbData,
            ref int pdwDataLen
            )
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptExportKey(
                        hKey,
                        hExpKey,
                        dwBlobType,
                        dwFlags,
                        pbData,
                        ref pdwDataLen
                    );
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptExportKey(
                        hKey,
                        hExpKey,
                        dwBlobType,
                        dwFlags,
                        pbData,
                        ref pdwDataLen
                    );
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptSetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, [In] uint dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }

        public bool CryptGetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, ref int pdwDataLen, [In] uint dwFlags)
        {
            switch (_pid)
            {
                case PlatformID.Win32NT:
                    return CryptoApiWindows.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
                case PlatformID.Unix:
                    return CryptoApiUnix.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
                default:
                    throw new PlatformNotSupportedException();
            }
        }


    }
}
