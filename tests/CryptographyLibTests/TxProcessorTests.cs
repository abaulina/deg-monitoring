using CryptographyLib;
using CryptographyLib.Models;
using FluentAssertions;
using Xunit;

namespace TxProcessorTests
{
    public class TxProcessorTests
    {
        [Fact]
        public async Task ShouldValidateTestData2022Async()
        {
            var txProcessor = new TxProcessor();

            await txProcessor.ProcessTxFiles(".\\..\\..\\..\\test_data-2022\\");

            var errorMessages = txProcessor.GetErrorMessages().ToList();
            var messages = await txProcessor.GetMessages();

            messages.Where(x => x.MessageType == LogMessageType.Error).Should().BeEmpty();
        }

        [Theory]
        [InlineData(".\\..\\..\\..\\test_data\\pool1\\")]
        [InlineData(".\\..\\..\\..\\test_data\\pool2\\")]
        public async Task ShouldValidateTestDataAsync(string path)
        {
            var txProcessor = new TxProcessor();

            await txProcessor.ProcessTxFiles(path);

            var errorMessages = txProcessor.GetErrorMessages().ToList();
            var messages = await txProcessor.GetMessages();

            messages.Where(x => x.MessageType == LogMessageType.Error).Should().BeEmpty();
        }

        [Theory]
        [InlineData(".\\..\\..\\..\\test_data\\pool_msk1\\")]
        [InlineData(".\\..\\..\\..\\test_data\\pool_msk2\\")]
        [InlineData(".\\..\\..\\..\\test_data\\pool_msk3\\")]
        [InlineData(".\\..\\..\\..\\test_data\\pool_msk4\\")]
        [InlineData(".\\..\\..\\..\\test_data\\pool_msk5\\")]
        public async Task ShouldValidateTestDataMskAsync(string path)
        {
            var txProcessor = new TxProcessor();

            await txProcessor.ProcessTxFiles(path);

            var errorMessages = txProcessor.GetErrorMessages().ToList();
            var messages = await txProcessor.GetMessages();

            //messages.Where(x => x.MessageType == LogMessageType.Error).Should().BeEmpty();
        }
    }
}