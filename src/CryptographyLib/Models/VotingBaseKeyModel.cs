using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CryptographyLib.Models
{
    public class VotingBaseKeyModel
    {
        [JsonConverter(typeof(DateTimeJsonConverter))]
        public DateTime? DateStart { get; set; }

        [JsonConverter(typeof(DateTimeJsonConverter))]
        public DateTime? DateEnd { get; set; }

        public int[][]? Dimension { get; set; }

        public string? BlindSigModulo { get; set; }

        public string? BlindSigExponent { get; set; }

        public string? BlindSigType { get; set; }

        public string[]? BlindSigParams { get; set; }
    }

    public class DateTimeJsonConverter : JsonConverter<DateTime?>
    {
        public override bool HandleNull => true;

        public override DateTime? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var input = reader.GetString();
            if (input == null)
            {
                return null;
            }

            return DateTime.ParseExact(input, "dd-MM-yyyy HH:mm:ss", null, DateTimeStyles.AdjustToUniversal);
        }

        public override void Write(Utf8JsonWriter writer, DateTime? dateTimeValue, JsonSerializerOptions options)
        {
            writer.WriteStringValue(dateTimeValue?.ToString("DD-MM-YYYY hh:mm:ss", CultureInfo.InvariantCulture));
        }
    }
}
