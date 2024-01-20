namespace CryptographyLib.Models
{
    public class ValidationResult
    {
        public string TxId { get; set; }

        public bool Valid { get; set; }

        public VotingOperation? Operation { get; set; }
    }
}
