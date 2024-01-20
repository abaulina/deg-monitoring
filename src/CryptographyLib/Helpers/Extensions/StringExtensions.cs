namespace CryptographyLib.Helpers.Extensions
{
    public static class StringExtensions
    {
        public static byte[] HexToByteArray(this string hex)
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

        public static string RemoveLeadingZeros(this string input)
        {
            var result = input.SkipWhile(x => x == '0').ToArray();

            return new string(result);
        }
    }
}
