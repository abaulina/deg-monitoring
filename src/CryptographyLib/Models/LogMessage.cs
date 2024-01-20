namespace CryptographyLib.Models
{
    public class LogMessage
    {
        public string Message { get; }
        public LogMessageType MessageType { get; }

        public LogMessage(string message, LogMessageType messageType)
        {
            Message = message;
            MessageType = messageType;
        }
    }

    public enum LogMessageType
    {
        Info,
        Error,
        Success,
        Benchmark
    }
}
