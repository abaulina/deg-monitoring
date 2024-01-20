using Google.Protobuf;

namespace CryptographyLib.Models;

public class Bulletin
{
    private Bulletin()
    {
        Questions = new List<Question>();
    }

    public List<Question> Questions { get; set; }

    public static Bulletin Decode(byte[] data, int length = -1)
    {
        var stream = new CodedInputStream(data);

        if (length == -1)
        {
            length = data.Length;
        }

        var bulletin = new Bulletin();

        while (stream.Position < length)
        {
            var b = stream.ReadUInt32();
            var tag = (byte)(b >> 3);
            switch (tag)
            {
                case 1:
                    bulletin.Questions.Add(Question.Decode(stream, (int)stream.ReadUInt32()));
                    break;
                default:
                    stream.SkipLastField();
                    break;
            }
        }

        return bulletin;
    }
}
