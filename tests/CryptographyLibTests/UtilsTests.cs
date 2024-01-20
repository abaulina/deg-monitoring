using CryptographyLib.Helpers;
using CryptographyLib.Helpers.CryptoApi;
using FluentAssertions;
using SimpleBase;
using System.Diagnostics;
using Xunit;

namespace CryptographyLibTests
{
    public class UtilsTests
    {
        private readonly TestFixture _fixture;
        private CryptoProHelper _cryptoProHelper;
        private CryptoApiProvider _cryptoApiProvider;

        public UtilsTests()
        {
            _fixture = new TestFixture();
            _cryptoApiProvider = new CryptoApiProvider();
            _cryptoProHelper = new CryptoProHelper();
        }

        [Fact]
        public void GetTotalTxCount_PerformanceTest()
        {
            var directory = ".\\..\\..\\..\\test_data-2022\\";
            var expectedCount = _cryptoProHelper.GetTotalTxCountOld(directory);

            var stopwatch = Stopwatch.StartNew();
            var actualCount = _cryptoProHelper.GetTotalTxCountOld(directory);
            stopwatch.Stop();

            Assert.Equal(expectedCount, actualCount);

            var oldTime = stopwatch.ElapsedMilliseconds;

            stopwatch = Stopwatch.StartNew();
            actualCount = _cryptoProHelper.GetTotalTxCount(directory);
            stopwatch.Stop();

            Assert.Equal(expectedCount, actualCount);

            var newTime = stopwatch.ElapsedMilliseconds;

            newTime.Should().BeLessThan(oldTime);
        }

        [Fact]
        public void StribogEquality()

        {
            var tx = _fixture.GetTx();
            var senderPublicKey = Base58.Bitcoin.Decode(tx.SenderPublicKey);
            var data = _cryptoProHelper.GetBytes(tx, senderPublicKey);

            var clock = new Stopwatch();
            clock.Start();
            var stribog = new Stribog();
            var hashedMessage = stribog.ComputeHash(data);
            clock.Stop();
            var elapsed = clock.ElapsedMilliseconds;

            clock.Restart();
            var stribogCPSharpei = new CryptoPro.Sharpei.Gost3411_2012_256CryptoServiceProvider();
            var hashedMessageCPSharpei = stribogCPSharpei.ComputeHash(data);
            clock.Stop();
            var elapsedCPSharpei = clock.ElapsedMilliseconds;

            clock.Restart();
            var stribogCP = new Gost3411_2012_256CryptoServiceProvider(_cryptoApiProvider);
            var hashedMessageCP = stribogCP.ComputeHash(data);
            clock.Stop();
            var elapsedCP = clock.ElapsedMilliseconds;

            var hex = Convert.ToHexString(hashedMessage);
            var hexCPSharpei = Convert.ToHexString(hashedMessageCPSharpei);
            var hexCP = Convert.ToHexString(hashedMessageCP);

            hexCP.Should().BeEquivalentTo(hexCPSharpei);
            hexCP.Should().BeEquivalentTo(hex);

            elapsedCP.Should().BeLessThan(elapsedCPSharpei);
            elapsedCP.Should().BeLessThan(elapsed);

            Console.WriteLine("Время работы Стрибог");
            Console.WriteLine($"CryptoAPI OS:   {elapsedCP} мс");
            Console.WriteLine($"CryptoPro .NET: {elapsedCPSharpei} мс");
            Console.WriteLine($"Самописная ф-я C#:  {elapsed} мс");
        }

    }
}
