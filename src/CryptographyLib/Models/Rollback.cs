namespace CryptographyLib.Models;

public class Rollback
{
    public string TxId { get; set; }

    public bool IsRollback { get; set; } = true;
}