namespace CryptographyLib.Models
{
    public class Tx
    {
        public string NestedTxId { get; set; }

        public int Type { get; set; }

        public string Signature { get; set; }

        public int Version { get; set; }

        public long Ts { get; set; }

        public string SenderPublicKey { get; set; }

        public long Fee { get; set; }

        public string? FeeAssetId { get; set; }

        public Dictionary<string, object> Params { get; set; }

        public Dictionary<string, object> Diff { get; set; }

        public JsonModel[] Raw { get; set; }

        public JsonExtraModel Extra { get; set; }

        public string ContractId { get; set; }

        public bool IsRollback { get; set; }

        public VotingOperation Operation { get; set; }
    }
}
