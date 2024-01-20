namespace CryptographyLib.Helpers.Extensions
{
    public static class ByteArrayExtensions
    {
        public static byte[] RemoveLeadingZeros(this byte[] byteArray)
        {
            var startIndex = 0;

            // Find the index of the first non-zero byte
            while (startIndex < byteArray.Length && byteArray[startIndex] == 0)
            {
                startIndex++;
            }

            // Create a new array without the leading zero bytes
            var length = byteArray.Length - startIndex;
            var result = new byte[length];
            Array.Copy(byteArray, startIndex, result, 0, length);

            return result;
        }
    }
}
