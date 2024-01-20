namespace CryptographyLib.Models;

public class BulletinsSum
{
    public AbBytes[][]? Acc { get; set; }

    public int Valid { get; set; }

    public List<string> Revoted { get; set; }

    public List<string> Voted { get; set; }
}