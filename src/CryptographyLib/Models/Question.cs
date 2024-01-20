using Google.Protobuf;

namespace CryptographyLib.Models;

public class Question
{
    public Question(List<RangeProof> options, RangeProof sum)
    {
        Options = options;
        Sum = sum;
    }

    private Question()
    {
        Options = new List<RangeProof>();
        Sum = new RangeProof();
    }

    public List<RangeProof> Options { get; set; }

    public RangeProof Sum { get; set; }

    public static Question Decode(CodedInputStream stream, int length)
    {
        var question = new Question();

        var end = stream.Position + length;

        while (stream.Position < end)
        {
            var bytes = stream.ReadUInt32();
            byte tag = (byte)(bytes >> 3);
            switch (tag)
            {
                case 1:
                    question.Options.Add(RangeProof.Decode(stream, (int)stream.ReadUInt32()));
                    break;
                case 2:
                    question.Sum = RangeProof.Decode(stream, (int)stream.ReadUInt32());
                    break;
                default:
                    stream.SkipLastField();
                    break;
            }
        }

        return question;
    }
}