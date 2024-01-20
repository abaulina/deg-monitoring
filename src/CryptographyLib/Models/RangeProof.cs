using Google.Protobuf;

namespace CryptographyLib.Models;

public class RangeProof
{
    public byte[] A { get; set; }
    public byte[] B { get; set; }
    public List<byte[]> As { get; set; } = new();
    public List<byte[]> Bs { get; set; } = new();
    public List<byte[]> C { get; set; } = new();
    public List<byte[]> R { get; set; } = new();

    public static RangeProof Decode(CodedInputStream stream, int length = -1)
    {
        var proof = new RangeProof();

        var end = stream.Position + length;

        while (stream.Position < end)
        {
            var b = stream.ReadUInt32();
            var tag = (byte)(b >> 3);
            switch (tag)
            {
                case 1:
                    proof.A = stream.ReadBytes().ToByteArray();
                    break;
                case 2:
                    proof.B = stream.ReadBytes().ToByteArray();
                    break;
                case 3:
                    proof.As.Add(stream.ReadBytes().ToByteArray());
                    break;
                case 4:
                    proof.Bs.Add(stream.ReadBytes().ToByteArray());
                    break;
                case 5:
                    proof.C.Add(stream.ReadBytes().ToByteArray());
                    break;
                case 6:
                    proof.R.Add(stream.ReadBytes().ToByteArray());
                    break;
                default:
                    stream.SkipLastField();
                    break;
            }
        }

        return proof;
    }
}