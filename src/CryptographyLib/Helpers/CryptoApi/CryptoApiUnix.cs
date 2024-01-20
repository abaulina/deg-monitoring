using System.Runtime.InteropServices;

namespace CryptographyLib.Helpers.CryptoApi;

public class CryptoApiUnix
{
    private const string LibName = "./Libs/libcapi10";

    [DllImport(LibName, CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptImportKey(
        IntPtr hProv,
        byte[] pbData,
        int dwDataLen,
        IntPtr hPubKey,
        int dwFlags,
        out IntPtr phKey);

    [DllImport(LibName, SetLastError = true, EntryPoint = "CryptAcquireContextA")]
    public static extern bool CryptAcquireContext(
        out IntPtr hProv,
        string? pszContainer,
        string? pszProvider,
        uint dwProvType,
        uint dwFlags);

    [DllImport(LibName, SetLastError = true)]
    public static extern bool CryptReleaseContext(
        IntPtr hProv,
        int dwFlags);

    [DllImport(LibName, SetLastError = true)]
    public static extern bool CryptDestroyKey(
        IntPtr hKey);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptExportPublicKeyInfo(
    IntPtr hCryptProv,
    uint dwKeySpec,
    uint dwCertEncodingType,
    IntPtr pInfo,
    ref uint pcbInfo);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptSetProvParam(IntPtr hProv, int dwParam, string pbData, int dwFlags);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptCreateHash(IntPtr hProv, int Algid, IntPtr hKey, int dwFlags, out IntPtr phHash);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptHashData(IntPtr hHash, byte[] pbData, int dwDataLen, int dwFlags);

    [DllImport(LibName, SetLastError = true, EntryPoint = "CryptVerifySignatureA")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptVerifySignature(
    IntPtr hHash,
    byte[] pbSignature,
    int dwSigLen,
    IntPtr hPubKey,
    string sDescription,
    int dwFlags);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptDestroyHash(IntPtr hHash);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptGetKeyParam(
      IntPtr hKey,
      int dwParam,
      ref IntPtr pbData,
      ref int pdwDataLen,
      int dwFlags
    );

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public unsafe static extern bool CryptSetKeyParam(
        IntPtr hKey,
        uint dwParam,
        CRYPT_DATA_BLOB* pbData,
        int dwFlags
    );
    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptExportKey(
        IntPtr hKey,
        IntPtr hExpKey,
        int dwBlobType,
        int dwFlags,
        byte[] pbData,
        ref int pdwDataLen
        );

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptSetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, [In] uint dwFlags);

    [DllImport(LibName, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CryptGetHashParam([In] IntPtr hHash, [In] uint dwParam, [In][Out] byte[] pbData, ref int pdwDataLen, [In] uint dwFlags);
}

