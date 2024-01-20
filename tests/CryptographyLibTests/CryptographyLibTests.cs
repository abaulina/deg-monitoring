using CryptographyLib.Helpers;
using CryptographyLib.Helpers.CryptoApi;
using CryptographyLib.Helpers.OpenSslApi;
using CryptographyLib.Models;
using FluentAssertions;
using Xunit;

namespace CryptographyLibTests;

public class CryptographyLibTests
{
    private readonly TestFixture _fixture;

    public CryptographyLibTests()
    {
        _fixture = new TestFixture();
    }


    [Fact]
    public void ShouldDecodeBulletin()
    {
        var vote = _fixture.GetTx();
        var binary = Convert.FromBase64String(vote.Params["vote"] as string ?? throw new InvalidOperationException());

        const string expected = "0aa40f0ada020a21" +
                                "039ce1bcfe784eef4895df78e1a24e265884b80d01c779ef70fea846d96ee522b9" +
                                "1221" +
                                "0322d084389f53baf940df36cc106016d739f4a4b40a16c2ec0eea6d1088fe745b" +
                                "1a21" +
                                "03d3aa073f615de24ad79084b0d462cfc713eafa1a7adc7a7e2cbbb669ba26787f" +
                                "1a21" +
                                "024d856740cd4065a11b3cfe5a2cfcaebf1fb768b23d5a24d593f1bf7319d908d0" +
                                "2221" +
                                "037192178280500d0cfb8931ca820d2c3149d5ee0fa52e7ae58f51b5cbcbbe05b4" +
                                "2221" +
                                "02dd4254c6ccf026a053bbe89bba417c872b329fa4aa12be934c84b37ca8a9585d" +
                                "2a20" +
                                "f0791a67ec3b52550404d959b7892216c3c3498d4034124e90b608a4db7756f8" +
                                "2a20" +
                                "9a3eca35f02592a3468559e0f3017110cbaf66ee415f2f02d5ea6560db734eac" +
                                "3220" +
                                "f8563a89700544b1d8972841e06eefe5c4cc87f15dd759286f54ee73601ba3f8" +
                                "3220" +
                                "d25db500d0f6ceb6846fc6896144642c4cfd0347dd01c129d4afb946877d53a2" +
                                "0ada020a2102c16f75ee43c01d3365fc172ce835f060fdf981a6dc8246dba23299a545bb66c5122102fec9231c4153f838d4dc963e3cd6922b713b53d7529562eadbaa63dcba9e529b1a2103" +
                                "02f29a07f2b6bb5c0cc635fd270a30ee618719398647ce9a91b1d62f7b4850751a21024f2ffa93574cf6d350dd42abfc096562f6401" +
                                "18aa80762b637dc289a221eabab222103e82044f9db6a60707552d2cff4a07ccb5838b6fdff1cef5961de3c673f0e436c222103b699" +
                                "f60a8cfc4b2e4919c1e9b41ad14afd9953ced32c676d0a7a110144f0edd82a20ab2d5deb5f6df4bb0c7146c9fb547a8d535274587a" +
                                "ac0b20016e9a312f2f74202a200d9319d315d59be755d651916040dd679e02b661b701810aabe88c20885654893220bfd7d99c9c3d" +
                                "46550c824c477d07074d47ed5d08f1312907d8edf2d611cf827f3220c0f726ea6d02c129cea3443e074940fb2abd4ef3d7e12f48c7" +
                                "1857a15c06e4f90ada020a2103dd589b8628da1e7531edde1c16d7d2e73f86b5ec953b711251d3764cae7b7ab412210366a6ad9b67" +
                                "59fe8cd2f583a6e60c4ab3dcead0851770aec4554082f88f01564d1a2103dd219d911c3ccb58f5a3bcf7cadbbdcd683778caee8521" +
                                "db15798279de0209121a210346cbeb0180afc77931494f83b41c82e2ac931de5a83725c8a0bd59c92f6f0aa5222102901a0d578103" +
                                "57319bd9b6d4f0b1f25c20d43c2ec231599085c7dcc3320b1a9b222103113ce7f985c8c9f391510247f904e4baabe9c811acfe8882" +
                                "b699a05e4f8b03da2a20090aee125e681adc3becd72f5ddc3e4427d2fccf234082e0bd7f1d23e6a4bdc12a20f19624d8e4967346c1e" +
                                "503aa3541060a187dc1519fd1482e55c82c98aa20a49632208583add081db7e2569762a46c7590faaf243c6425d748903791051411" +
                                "c6d4f7732208a2368bccda8ef2b919d88115b975252e445ff5b683a6f374f3dc6bf949d451f0ada020a2103a21b66b6278286e899f" +
                                "580f4f6382f0ed3064935c22f83ee8668d6c89944e2b1122102916a54659a2c069e64d46eeb204008bf87a2cdaa426c228fdedf5f0" +
                                "b2e02faa11a21024c41bd6d849fb1f1a58399313b31f20211d467bdd795786a7e56797ee537bd411a21020c4a68139fbf3c8d910ac" +
                                "59a8e19128271b0af3e9f977acdb55e2d1a68134393222102b863da1468d6fa86d656cfae1e891501045b49eed1cbe00a5a0f422b2" +
                                "b67df3a2221023b23fafabc08f5ecf199180261ca6d76b4ed01faef3690445eea964049a9d6832a20e39798e727c6f41ca4d70ec207" +
                                "3bd1231fbbb771c11892d95a5de72769ae0f082a20a7dfe9dda562eee9ba7250e31b8857afa7862025da7ce5cfd18428a5fc3d17c53" +
                                "220ae002c79a6215a3079f0250e751497521b40084d5d00d8457f919775e91f334432201ed2dc7e9a43c6c3a0e7c21c16e8f5e8a107" +
                                "37b79bee2af2656f96107ac9fab20ada020a2102613d909916960e1142cc31e66b98292c65f11ccbd9f4a57e7bfdf638965a05ea122" +
                                "103821234331e11dabe5a0242ba65c9fcd341d30851a376276317bcef76c6a89a981a21034654acdbe6c6f23de9bca95b6d9c0aac4" +
                                "644018302c9b0f2b92c532983771b251a21029001a992db04236b06a7ba1fd4182a7577e695a31bd79d5b787ca7cb9b10456b22210" +
                                "29123234f836dd46b6468ee44c841c219c98932d224a73af6b8926f0ca9b198f1222102ba7f54c36ace8239cbf30afcb6b3f5cb02c" +
                                "9b6f8d8365d1b98bc466485dc01f62a20c71c4c146f380ac9fd19980d827f7f4d9e4a8ee6a5ce8cf55c15f70cba6e7f2e2a20a769" +
                                "b2c8efb18e02532b20e767a7f86d9dc589cad90d078bbd1a792208a27ccd3220b863027b5cab898e977bd2053b549691a1df0be93" +
                                "eb79ebb0c01e2ec981e21a73220df6a9ccf2133319aece56c809a2d5df57747f37f0fdef42db7e0bb37ad93edb612d0010a2103463" +
                                "35ee64365414a6858b81b7f3c725ac9e6421ac8a79b0b32481bc2c8acc5de122103838c8ad81068e6335f7f0363a0debf2448cb74e" +
                                "0d8deb9aa27baeddfc55d40401a21030251d3695a89e3d438452ac13d1037b5ace53634bf7c065da89654208d8e9b29222102d3937" +
                                "b1f3013fd1c2163b76014eac44887b0ed9b05b872eb99bd8d948b66b27c2a202d03bdb59fcce758ceeec34fb0719943452ffc87e43" +
                                "4af726aede0ed54f296263220976ebb12b2578c6cc64772a725c4f0c6324021ddc765c2f94a1c6a043ebf8df7";

        var converted = BitConverter.ToString(binary).Replace("-", "");
        converted.Should().Be(expected.ToUpper());
    }

    [Fact]
    public void ShouldGetBulletinFromBytes()
    {
        var vote = _fixture.GetTx();
        var binary = Convert.FromBase64String(vote.Params["vote"] as string ?? throw new InvalidOperationException());

        var bulletin = Bulletin.Decode(binary);

        bulletin.Questions.Count.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task ShouldValidateTxSignature()
    {
        var validationHelper = _fixture.GetValidationHelper();
        var tx = _fixture.GetTx();

        var result = await validationHelper.ValidateTxSignature(tx);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldValidateBulletin()
    {
        var validationHelper = _fixture.GetValidationHelper();

        var tx = _fixture.GetTx();
        var mainKey = _fixture.GetMainKey();
        var dimension = _fixture.GetDimension();

        var result = await validationHelper.ValidateBulletin(tx, mainKey, dimension);

        result.Valid.Should().BeTrue();
    }

    [Fact]
    public Task ShouldCalculateResults()
    {

        var abSumsInner = new AbBytes[] {new()
        {
            A = Convert.FromHexString("0228408d0b23236106a07b3e2678adb2bd65c079cd4bf293a02aebd7b9299fa471"),
            B = Convert.FromHexString("03e7db820cb3e0981a51fc5df8db27d69c88e96c29524c44dfa0a2babc7ebc3f06")
        },
        new()
        {
            A = Convert.FromHexString("038933f5ee3ac086281fe183f15aa2a7a1d949dd3d83fcc08a251878fe26166964"),
            B = Convert.FromHexString("03038118774150a07133f6de6e49c6585716493a008ed0accc082d99c53d3869d9")
        },new()
        {
            A = Convert.FromHexString("02cae5a34394552350e7ea88ed304c9369e9a5ef1846c17a450962fb9e12df483d"),
            B = Convert.FromHexString("0274d3676f5b2c82bf3832525ab27c3ae03433f43d186b867c8cfd5577a07e47f9")
        },
        new()
        {
            A = Convert.FromHexString("03275b95799f7f812e6cb8a4bfd49326f202dfb0c237b4b3e3f319851917255128"),
            B = Convert.FromHexString("02197457d22cc0d5207d839963e9d64e2e0b1005beece674eb47cba55265bf5b50")
        },
        new()
        {
            A = Convert.FromHexString("03c8b539396defe0cf456881d383aa85816abae287c5460c1845afdd617f7fd910"),
            B = Convert.FromHexString("02b914bb8f2ba0214b0318b4324c1f1d595e99ae9aae6b2c0ec91976a53a11d305")
        }

        };

        var abSums = new AbBytes[1][] { abSumsInner };

        var dimensions = new List<int>() { 1, 1, 5 };
        var n = 67;

        var masterPublicKey = Convert.FromHexString("03d1dc7d489f00983705de6acfd5dc75951a827c30a731a23e5478731f84a064e5");
        var commissionPublicKey = Convert.FromHexString("03f6c599d3f275cf217ea0eb182d756ce6e86e385ee487641f750c30dac51c19ef");

        var masterDecryptionInner = new Decryption[] { new()
        {
            P = "035aa9a5cf0c29645384cc4e5fa86b54a354c26b9c8d3d994ad3804f5314a30328",
            U1 = "03f961ea7032f265e4414f2feced2992eae0c2e8ce7abadc2947910edeca9a4949",
            U2 = "03aa5cd48792edf4dee793a5e905840889b7e4873c90c0ca903fa4a8a4d89889e9",
            W = "74b09482ba120573b21a2ce8d576796ecb705be0d427a193386091313b6a3cef"
        },new()
        {
            P = "021f95d54445b541ec5eb765e53457b00d0f16b2fb087c7c8952ca483a0b6cad08",
            U1 = "03d5eb9c9add684e7fe95d54e9512e00805aff093d4b80a9ef8d9f015acc9b41a2",
            U2 = "03457146e0b72a84a3e94ef95ccad7a729ba955691f30861bef3d6569705537359",
            W = "60642014f4b033e7664728e0dfd59aea056c94cedaa1a9f4f363d2fcc809c0c4"
        },new()
        {
            P = "038627c9fe5d2684b284ce458e5dbafad03edc38e5933cd9d6bb3767cca2167b7e",
            U1 = "0387863145c944599d6186e807d705ccd46f9325fb9eddbde43427d51b52ce0c63",
            U2 = "03d739530ecc8abebd1986d3a58c3d5b1b48da8610f1130b67f14e7700856c8a31",
            W = "b591224fc29aeda65e71b2528465c585fa5085332901ac9bc247e805093564ec"
        },new()
        {
            P = "0237d7af7f6d99808e99a9cfcea1ee10a4e172c4bc9066174b9454850f58cef429",
            U1 = "021c9d7d3c76f872fc25a5e6a71bb5c2074af2ee257831559d9390a020b324e7e1",
            U2 = "030386cb55eaf84f8c32d6d6a52a3d87ca9ab7bd2e36dba797111589046032e8f2",
            W = "a6c367942ba1abe4d15dec0e7325b4b5ef35cf96398aeec57e56cc2845fc8084"
        },
        new()
        {
            P = "02e89422c43c437b9dd10d9a89741ef1190b241339e00b6546dce9540c652a436e",
            U1 = "0270b26ee0dddb351d8120c4392974de827ffddec5f51d57d869de69aec85ba9c3",
            U2 = "038a8f7bd08481263934a40d283c206e9bc0eaf154604a9accfb73d0c691fae72c",
            W = "1fe0ec1229c6dd866ff1caa232250ebba193dfcc2db90fd296e5bcdb1b0877dd"
        }
        };

        var masterDecryption = new[] { masterDecryptionInner };


        var commissionDecryptionInner = new Decryption[] {new()
        {
            P = "02477ff7f44c6a5bbb2456853221040d52bc0054056e2469cd26480d29a574c250",
            U1 = "03f1b8394b971adfc1a57fc206728d61d431e3d9d315d2fcee4af64cb16b092bf0",
            U2 = "03ec60c3bad21b87e25fe551836aa8681849f6e8397cf3bdaedfd191f70fb9f449",
            W = "4722a21f8da14f9cea5fe154fbeabec655481530a89da38366b5357163904840"
        },new()
        {
            P = "033b9bc7ffb31e360e9406043f930e1aaf946fb9845cda99d9026811010dc27a19",
            U1 = "0254dce999dbf4b9cadbb145e338775a5c2119db4f1dfae1fac8dd04d54e629ced",
            U2 = "03d84c5d96da284156b2b7f0878849134c0eb87a3d6579d009744b238d65914c60",
            W = "89835b8195d2b20b28ebd260394aed8b9179cb47cae890ae2ce16ef337d9ca4b"
        },new()
        {
            P = "03317846ad0be7624bbad2e6b47c26f30d937261c6a0f96c3e185e0150f3611417",
            U1 = "0364ed1df6569e8b89dd2a81356ac0ab1312d6e2c67db157cd4d7614702dce10ab",
            U2 = "02b43e97bb87cc7ff3ac34d9fea6d44dbce2b2b4f58c668e511103e63d9e709054",
            W = "43d3afabd6391052066dae1b3feea6e0a6068c55ae5551e5131fd2bcd6326a5b"
        },
        new()
        {
            P = "023dff785985b28023c08c7d4ea516c5cef559220c0c0171c955474e4811613993",
            U1 = "023e558ec83ca433e00c6983d55293fe04d90eab5d94e5d5060360483492571afd",
            U2 = "02a46aa002c1e1e7b59df89ddb8281632908f626f1bc39b674689255de4802f64d",
            W = "b858cc213e6e0354f8ed5f03291ac1dca29d747b56cceddd2a812564e49689a4"
        },new()
        {
            P = "0327ee652f700af53389f5f3e18441f48e3fdbbdcc24a404f3b50540a929418dc0",
            U1 = "03e57f4ff72587f4a1996dcb6c4a4a2a146fdc83199d3beb52a25036fe8c67c279",
            U2 = "02aefd1f597a754195d489e792bc6fada5d6446fc2de61d40653f79c0d4fb2c01c",
            W = "59adda7d731d1884126e92afcfb1543bd03b5fa618487ee53c971c07873f77e0"
        }
        };
        var commissionDecryption = new Decryption[1][] { commissionDecryptionInner };

        var validationHelper = _fixture.GetValidationHelper();

        var result = validationHelper.CalculateResults(abSums, dimensions, n, masterPublicKey, masterDecryption, commissionPublicKey, commissionDecryption);

        result[0][0].Should().NotBe(0);
        return Task.CompletedTask;
    }

    [Fact]
    public void ShouldGetQs()
    {
        var validationHelper = _fixture.GetValidationHelper();
        var cryptoApiProvider = new CryptoApiProvider();
        var cryptoProHelper = new CryptoProHelper();
        var openSslApiProvider = new OpenSslApiProvider();

        var pCurve = cryptoProHelper.create_curve();
        var ctx = openSslApiProvider.BN_CTX_new();

        var hash1 = Convert.FromHexString("c988027e0db1663861d615865c84b95dbda940f34d0499b446a5b1e62fc62b54");
        var hash2 = Convert.FromHexString("bdada2ed67b6964b6239ac586d9f26052e0a5baebd683c7c0e9624bb7cbd701c");

        var masterDecryption = Convert.FromHexString("035aa9a5cf0c29645384cc4e5fa86b54a354c26b9c8d3d994ad3804f5314a30328");
        var commissionDecryption = Convert.FromHexString("02477ff7f44c6a5bbb2456853221040d52bc0054056e2469cd26480d29a574c250");
        var sum = Convert.FromHexString("03e7db820cb3e0981a51fc5df8db27d69c88e96c29524c44dfa0a2babc7ebc3f06");

        var h1 = openSslApiProvider.BN_new(); //
        var h2 = openSslApiProvider.BN_new(); //

        if (IntPtr.Zero == (h1 = openSslApiProvider.BN_bin2bn(hash1, hash1.Length, IntPtr.Zero))) throw new Exception();
        if (IntPtr.Zero == (h2 = openSslApiProvider.BN_bin2bn(hash2, hash2.Length, IntPtr.Zero))) throw new Exception();

        var point1 = validationHelper.CreatePoint(pCurve, masterDecryption);
        var P1 = openSslApiProvider.EC_POINT_new(pCurve);
        openSslApiProvider.EC_POINT_mul(pCurve, P1, IntPtr.Zero, point1, h1, ctx);


        var point2 = validationHelper.CreatePoint(pCurve, commissionDecryption);
        var P2 = openSslApiProvider.EC_POINT_new(pCurve);
        openSslApiProvider.EC_POINT_mul(pCurve, P2, IntPtr.Zero, point2, h2, ctx);

        var C = openSslApiProvider.EC_POINT_new(pCurve);
        openSslApiProvider.EC_POINT_add(pCurve, C, P1, P2, ctx);
        var pointToCompare = validationHelper.CreatePoint(pCurve, sum);

        if (openSslApiProvider.EC_POINT_cmp(pCurve, C, pointToCompare, ctx) == 0)
        {

        }
        else
        {
            openSslApiProvider.EC_POINT_invert(pCurve, C, ctx);

            openSslApiProvider.EC_POINT_add(pCurve, C, pointToCompare, C, ctx);

            cryptoProHelper.EC_POINT2binBECompressed(cryptoProHelper.create_curve(), C, out var p_PointX, out var flag);

            if (flag == 0)
            {
                p_PointX[0] = 0x02;
            }
            else
            {
                p_PointX[0] = 0x03;
            }

            var hex = Convert.ToHexString(p_PointX).ToLower();
            hex.Should().Be("039ef444cf21ea00ac4f5242dedcb807cc6999957d2ca2952452c3dec5e94d8830");
        }
    }

}
