using CryptographyLib;
using CryptographyLib.Helpers;
using CryptographyLib.Models;
using Moq;

namespace CryptographyLibTests
{
    public class TestFixture
    {
        public string GetMainKey()
        {
            return "02012ffb74e7da432272c7dd76148d5a58d049c47628745c1cb399feb4d0d67ddf";
        }

        public int[][] GetDimension()
        {
            var array = new int[1][];
            array[0] = new[] { 1, 1, 5 };
            return array;
        }

        public Tx GetTx()
        {
            var tx = new Tx();
            tx.NestedTxId = "AYvMkdqmGB61WeN1zp7G1EGV41LebmeBGbXHBfiXDrxD";
            tx.Extra = new JsonExtraModel { ContractVersion = 1 };
            tx.ContractId = "C2PNTNPsNdVycjJs7BRD7aixkmPPbxj7PWjCxbo7ikC4";
            tx.Type = 104;
            tx.Signature = "3yZ4xTJbqASpceA6NtMDhGyX5HyPrL2Paiq9D3Q4WFiEEbvofSt4wJCzZW5ndgZSVU14WtvkbbSuUonenc1J2bVx";
            tx.Version = 4;
            tx.Ts = 1679065935000;
            tx.IsRollback = false;
            tx.Operation = VotingOperation.Vote;
            tx.SenderPublicKey = "4k9XXHkdnoggJGhHrsv7Qxp6VKzMA2c8sYVvBqy6WQHAKgAy3jsQSySh9xdpLd4aKrpXKkZnMRd5EYYQmMytWmmV";
            tx.Fee = 0;
            tx.FeeAssetId = "";
            tx.Params = new Dictionary<string, object>
        {
            { "operation", "vote" },
            {
                "vote", "CqQPCtoCCiEDnOG8/nhO70iV33jhok4mWIS4DQHHee9w/qhG2W7lIrkSIQMi0IQ4n1O6+UDfNswQYBbXOfSktAoWwuwO6" +
                        "m0QiP50WxohA9OqBz9hXeJK15CEsNRiz8cT6voaetx6fiy7tmm6Jnh/GiECTYVnQM1AZaEbPP5aLPyuvx+3aLI9WiTVk/" +
                        "G/cxnZCNAiIQNxkheCgFANDPuJMcqCDSwxSdXuD6UueuWPUbXLy74FtCIhAt1CVMbM8CagU7vom7pBfIcrMp+kqhK+k0y" +
                        "Es3yoqVhdKiDweRpn7DtSVQQE2Vm3iSIWw8NJjUA0Ek6Qtgik23dW+Cogmj7KNfAlkqNGhVng8wFxEMuvZu5BXy8C1epl" +
                        "YNtzTqwyIPhWOolwBUSx2JcoQeBu7+XEzIfxXddZKG9U7nNgG6P4MiDSXbUA0PbOtoRvxolhRGQsTP0DR90BwSnUr7lGh" +
                        "31TograAgohAsFvde5DwB0zZfwXLOg18GD9+YGm3IJG26IymaVFu2bFEiEC/skjHEFT+DjU3JY+PNaSK3E7U9dSlWLq26" +
                        "pj3LqeUpsaIQMC8poH8ra7XAzGNf0nCjDuYYcZOYZHzpqRsdYve0hQdRohAk8v+pNXTPbTUN1Cq/wJZWL2QBGKqAditjf" +
                        "cKJoiHqurIiED6CBE+dtqYHB1UtLP9KB8y1g4tv3/HO9ZYd48Zz8OQ2wiIQO2mfYKjPxLLkkZwem0GtFK/ZlTztMsZ20K" +
                        "ehEBRPDt2Cogqy1d619t9LsMcUbJ+1R6jVNSdFh6rAsgAW6aMS8vdCAqIA2TGdMV1ZvnVdZRkWBA3WeeArZhtwGBCqvoj" +
                        "CCIVlSJMiC/19mcnD1GVQyCTEd9BwdNR+1dCPExKQfY7fLWEc+CfzIgwPcm6m0CwSnOo0Q+B0lA+yq9TvPX4S9IxxhXoV" +
                        "wG5PkK2gIKIQPdWJuGKNoedTHt3hwW19LnP4a17JU7cRJR03ZMrnt6tBIhA2amrZtnWf6M0vWDpuYMSrPc6tCFF3CuxFV" +
                        "AgviPAVZNGiED3SGdkRw8y1j1o7z3ytu9zWg3eMruhSHbFXmCed4CCRIaIQNGy+sBgK/HeTFJT4O0HILirJMd5ag3Jci" +
                        "gvVnJL28KpSIhApAaDVeBA1cxm9m21PCx8lwg1DwuwjFZkIXH3MMyCxqbIiEDETzn+YXIyfORUQJH+QTkuqvpyBGs/oiC" +
                        "tpmgXk+LA9oqIAkK7hJeaBrcO+zXL13cPkQn0vzPI0CC4L1/HSPmpL3BKiDxliTY5JZzRsHlA6o1QQYKGH3BUZ/RSC5Vy" +
                        "CyYqiCkljIghYOt0IHbfiVpdipGx1kPqvJDxkJddIkDeRBRQRxtT3cyIIojaLzNqO8rkZ2IEVuXUlLkRf9baDpvN089xr" +
                        "+UnUUfCtoCCiEDohtmtieChuiZ9YD09jgvDtMGSTXCL4PuhmjWyJlE4rESIQKRalRlmiwGnmTUbusgQAi/h6LNqkJsIo/" +
                        "e318LLgL6oRohAkxBvW2En7HxpYOZMTsx8gIR1Ge915V4an5WeX7lN71BGiECDEpoE5+/PI2RCsWajhkSgnGwrz6fl3rN" +
                        "tV4tGmgTQ5MiIQK4Y9oUaNb6htZWz64eiRUBBFtJ7tHL4ApaD0IrK2ffOiIhAjsj+vq8CPXs8ZkYAmHKbXa07QH67zaQR" +
                        "F7qlkBJqdaDKiDjl5jnJ8b0HKTXDsIHO9EjH7u3ccEYktlaXecnaa4PCCogp9/" +
                        "p3aVi7um6clDjG4hXr6eGICXafOXP0YQopfw9F8UyIK4ALHmmIVowefAlDnUUl1IbQAhNXQDYRX" +
                        "+Rl3XpHzNEMiAe0tx+mkPGw6DnwhwW6PXooQc3t5vuKvJlb5YQesn6sgraAgohAmE9kJkWlg4RQswx5muYKSxl8RzL2fS" +
                        "lfnv99jiWWgXqEiEDghI0Mx4R2r5aAkK6Zcn800HTCFGjdidjF7zvdsaompgaIQNGVKzb5sbyPem8qVttnAqsRkQBgwLJ" +
                        "sPK5LFMpg3cbJRohApABqZLbBCNrBqe6H9QYKnV35pWjG9edW3h8p8ubEEVrIiECkSMjT4Nt1GtkaO5EyEHCGcmJMtIkp" +
                        "zr2uJJvDKmxmPEiIQK6f1TDas6COcvzCvy2s/XLAsm2+Ng2XRuYvEZkhdwB9iogxxxMFG84Csn9GZgNgn9/TZ5Kjualzo" +
                        "z1XBX3DLpufy4qIKdpssjvsY4CUysg52en+G2dxYnK2Q0Hi70aeSIIonzNMiC4YwJ7XKuJjpd70gU7VJaRod8L6T63nrs" +
                        "MAeLsmB4hpzIg32qczyEzMZrs5WyAmi1d9XdH838P3vQtt+C7N62T7bYS0AEKIQNGM17mQ2VBSmhYuBt/PHJayeZCGsin" +
                        "mwsySBvCyKzF3hIhA4OMitgQaOYzX38DY6DevyRIy3Tg2N65qie67d/FXUBAGiEDAlHTaVqJ49Q4RSrBPRA3tazlNjS/f" +
                        "AZdqJZUII2OmykiIQLTk3sfMBP9HCFjt2AU6sRIh7DtmwW4cuuZvY2Ui2ayfCogLQO9tZ/M51jO7sNPsHGZQ0Uv/IfkNK" +
                        "9yau3g7VTyliYyIJduuxKyV4xsxkdypyXE8MYyQCHdx2XC+UocagQ+v433"
            },
            {
                "blindSig",
                "AaKcVwrSDFjEG6mTAZkwmoORgsu8engUAlv1lMYmadUN72U7schUTKbNAULvRy3NBZmo1HU7sXgCbkhIZNgLFj77K4jFncRl22R" +
                "UzECKe+xGfI2pK/lI7K+iMvQ/Zuqu5ANmmyBld4kkXweIaQeyDi/f7yzBrAKIb4n8co/etZg13RQNGWHcu+ysOIJDyelQyG9SMo" +
                "dVjHivnfFUYGOuwrzZ2J7RSrd+2Ihxhr8u/kViPG/0YOX0jAKDKhCNeHlg/vQ/FjIJ6F9sqI6mlb3MWicCsxQ9rTLBxzaZR8Txi" +
                "v501I3uIQAm84eZToluhKraAUMFRi4n5BlDYeg3eHBTACxHs0ybrH3FBQCm9zR3q811REDv/Mr9PKxFBvhDWDki+tQGHU0Fzi3U" +
                "Ecd1FNJNYifLuZUcaYmzqL0jjUgRa2PuoBos8bFbIleb4trsgC6nl2tMv9vDKfXtvAhm74teHtaPRLjcI8UDUBkBWSLk6JjDWsD" +
                "CbJfY/8Qsj7DEtZI6Nk8cy9KUcIJ9SsEyxSOaYNFsio1QmqjKQUScXiBj370TDlOr63iuRt/xS1u5Q41mnTf3FotISJZ6f7ksUy" +
                "3J1QNgkrShjLtSM+cmAh9qpz4TMK+Vy9J/YD1l4WB43QaHOtlbbYu18j7JLQ58IQxnJXHn428eOx2nZN6o7CHd9uA="
            }
        };
            tx.Diff = new Dictionary<string, object>
        {
            {
                "VOTE_4k9XXHkdnoggJGhHrsv7Qxp6VKzMA2c8sYVvBqy6WQHAKgAy3jsQSySh9xdpLd4aKrpXKkZnMRd5EYYQmMytWmmV",
                "{\"vote\":\"AYvMkdqmGB61WeN1zp7G1EGV41LebmeBGbXHBfiXDrxD\",\"blindSig\":\"1a29c570ad20c58c41ba9" +
                "930199309a839182cbbc7a7814025bf594c62669d50def653bb1c8544ca6cd0142ef472dcd0599a8d4753bb178026e48" +
                "4864d80b163efb2b88c59dc465db6454cc408a7bec467c8da92bf948ecafa232f43f66eaaee403669b20657789245f0" +
                "7886907b20e2fdfef2cc1ac02886f89fc728fdeb59835dd140d1961dcbbecac388243c9e950c86f523287558c78af9df" +
                "1546063aec2bcd9d89ed14ab77ed8887186bf2efe45623c6ff460e5f48c02832a108d787960fef43f163209e85f6ca88" +
                "ea695bdcc5a2702b3143dad32c1c7369947c4f18afe74d48dee210026f387994e896e84aada014305462e27e4194361" +
                "e837787053002c47b34c9bac7dc50500a6f73477abcd754440effccafd3cac4506f843583922fad4061d4d05ce2dd411" +
                "c77514d24d6227cbb9951c6989b3a8bd238d48116b63eea01a2cf1b15b22579be2daec802ea7976b4cbfdbc329f5edbc" +
                "0866ef8b5e1ed68f44b8dc23c5035019015922e4e898c35ac0c26c97d8ffc42c8fb0c4b5923a364f1ccbd29470827d4a" +
                "c132c5239a60d16c8a8d509aa8ca41449c5e2063dfbd130e53abeb78ae46dff14b5bb9438d669d37f7168b4848967a7f" +
                "b92c532dc9d5036092b4a18cbb5233e726021f6aa73e1330af95cbd27f603d65e16078dd06873ad95b6d8bb5f23ec92d" +
                "0e7c210c672571e7e36f1e3b1da764dea8ec21ddf6e0\"}"
            }
        };
            tx.Raw = new[]
            {
            new JsonModel { Key = "operation", StringValue = "vote" },
            new JsonModel
            {
                Key = "vote",
                BinaryValue =
                    "CqQPCtoCCiEDnOG8/nhO70iV33jhok4mWIS4DQHHee9w/qhG2W7lIrkSIQMi0IQ4n1O6+UDfNswQYBbXOfSkt" +
                    "AoWwuwO6m0QiP50WxohA9OqBz9hXeJK15CEsNRiz8cT6voaetx6fiy7tmm6Jnh/GiECTYVnQM1AZaEbPP5aLPy" +
                    "uvx+3aLI9WiTVk/G/cxnZCNAiIQNxkheCgFANDPuJMcqCDSwxSdXuD6UueuWPUbXLy74FtCIhAt1CVMbM8CagU" +
                    "7vom7pBfIcrMp+kqhK+k0yEs3yoqVhdKiDweRpn7DtSVQQE2Vm3iSIWw8NJjUA0Ek6Qtgik23dW+Cogmj7KNf" +
                    "AlkqNGhVng8wFxEMuvZu5BXy8C1eplYNtzTqwyIPhWOolwBUSx2JcoQeBu7+XEzIfxXddZKG9U7nNgG6P4MiDS" +
                    "XbUA0PbOtoRvxolhRGQsTP0DR90BwSnUr7lGh31TograAgohAsFvde5DwB0zZfwXLOg18GD9+YGm3IJG26IymaV" +
                    "Fu2bFEiEC/skjHEFT+DjU3JY+PNaSK3E7U9dSlWLq26pj3LqeUpsaIQMC8poH8ra7XAzGNf0nCjDuYYcZOYZHzpq" +
                    "RsdYve0hQdRohAk8v+pNXTPbTUN1Cq/wJZWL2QBGKqAditjfcKJoiHqurIiED6CBE+dtqYHB1UtLP9KB8y1g4tv" +
                    "3/HO9ZYd48Zz8OQ2wiIQO2mfYKjPxLLkkZwem0GtFK/ZlTztMsZ20KehEBRPDt2Cogqy1d619t9LsMcUbJ+1R6jV" +
                    "NSdFh6rAsgAW6aMS8vdCAqIA2TGdMV1ZvnVdZRkWBA3WeeArZhtwGBCqvojCCIVlSJMiC/19mcnD1GVQyCTEd9Bw" +
                    "dNR+1dCPExKQfY7fLWEc+CfzIgwPcm6m0CwSnOo0Q+B0lA+yq9TvPX4S9IxxhXoVwG5PkK2gIKIQPdWJuGKNoedT" +
                    "Ht3hwW19LnP4a17JU7cRJR03ZMrnt6tBIhA2amrZtnWf6M0vWDpuYMSrPc6tCFF3CuxFVAgviPAVZNGiED3SGdkR" +
                    "w8y1j1o7z3ytu9zWg3eMruhSHbFXmCed4CCRIaIQNGy+sBgK/HeTFJT4O0HILirJMd5ag3JcigvVnJL28KpSIhAp" +
                    "AaDVeBA1cxm9m21PCx8lwg1DwuwjFZkIXH3MMyCxqbIiEDETzn+YXIyfORUQJH+QTkuqvpyBGs/oiCtpmgXk+LA9o" +
                    "qIAkK7hJeaBrcO+zXL13cPkQn0vzPI0CC4L1/HSPmpL3BKiDxliTY5JZzRsHlA6o1QQYKGH3BUZ/RSC5VyCyYqiCk" +
                    "ljIghYOt0IHbfiVpdipGx1kPqvJDxkJddIkDeRBRQRxtT3cyIIojaLzNqO8rkZ2IEVuXUlLkRf9baDpvN089xr+UnU" +
                    "UfCtoCCiEDohtmtieChuiZ9YD09jgvDtMGSTXCL4PuhmjWyJlE4rESIQKRalRlmiwGnmTUbusgQAi/h6LNqkJsIo/" +
                    "e318LLgL6oRohAkxBvW2En7HxpYOZMTsx8gIR1Ge915V4an5WeX7lN71BGiECDEpoE5+/PI2RCsWajhkSgnGwrz6fl" +
                    "3rNtV4tGmgTQ5MiIQK4Y9oUaNb6htZWz64eiRUBBFtJ7tHL4ApaD0IrK2ffOiIhAjsj+vq8CPXs8ZkYAmHKbXa07QH" +
                    "67zaQRF7qlkBJqdaDKiDjl5jnJ8b0HKTXDsIHO9EjH7u3ccEYktlaXecnaa4PCCogp9/p3aVi7um6clDjG4hXr6eGI" +
                    "CXafOXP0YQopfw9F8UyIK4ALHmmIVowefAlDnUUl1IbQAhNXQDYRX+Rl3XpHzNEMiAe0tx+mkPGw6DnwhwW6PXooQc" +
                    "3t5vuKvJlb5YQesn6sgraAgohAmE9kJkWlg4RQswx5muYKSxl8RzL2fSlfnv99jiWWgXqEiEDghI0Mx4R2r5aAkK6Z" +
                    "cn800HTCFGjdidjF7zvdsaompgaIQNGVKzb5sbyPem8qVttnAqsRkQBgwLJsPK5LFMpg3cbJRohApABqZLbBCNrBqe6" +
                    "H9QYKnV35pWjG9edW3h8p8ubEEVrIiECkSMjT4Nt1GtkaO5EyEHCGcmJMtIkpzr2uJJvDKmxmPEiIQK6f1TDas6COc" +
                    "vzCvy2s/XLAsm2+Ng2XRuYvEZkhdwB9iogxxxMFG84Csn9GZgNgn9/TZ5Kjualzoz1XBX3DLpufy4qIKdpssjvsY4CU" +
                    "ysg52en+G2dxYnK2Q0Hi70aeSIIonzNMiC4YwJ7XKuJjpd70gU7VJaRod8L6T63nrsMAeLsmB4hpzIg32qczyEzMZrs5" +
                    "WyAmi1d9XdH838P3vQtt+C7N62T7bYS0AEKIQNGM17mQ2VBSmhYuBt/PHJayeZCGsinmwsySBvCyKzF3hIhA4OMitgQ" +
                    "aOYzX38DY6DevyRIy3Tg2N65qie67d/FXUBAGiEDAlHTaVqJ49Q4RSrBPRA3tazlNjS/fAZdqJZUII2OmykiIQLTk3sf" +
                    "MBP9HCFjt2AU6sRIh7DtmwW4cuuZvY2Ui2ayfCogLQO9tZ/M51jO7sNPsHGZQ0Uv/IfkNK9yau3g7VTyliYyIJduuxKy" +
                    "V4xsxkdypyXE8MYyQCHdx2XC+UocagQ+v433"
            },
            new JsonModel
            {
                Key = "blindSig",
                BinaryValue = "AaKcVwrSDFjEG6mTAZkwmoORgsu8engUAlv1lMYmadUN72U7schUTKbNAULvRy3NBZmo1HU7sXgCbkhIZNgLF" +
                              "j77K4jFncRl22RUzECKe+xGfI2pK/lI7K+iMvQ/Zuqu5ANmmyBld4kkXweIaQeyDi/f7yzBrAKIb4n8co/etZ" +
                              "g13RQNGWHcu+ysOIJDyelQyG9SModVjHivnfFUYGOuwrzZ2J7RSrd+2Ihxhr8u/kViPG/0YOX0jAKDKhCNeHl" +
                              "g/vQ/FjIJ6F9sqI6mlb3MWicCsxQ9rTLBxzaZR8Txiv501I3uIQAm84eZToluhKraAUMFRi4n5BlDYeg3eHB" +
                              "TACxHs0ybrH3FBQCm9zR3q811REDv/Mr9PKxFBvhDWDki+tQGHU0Fzi3UEcd1FNJNYifLuZUcaYmzqL0jjUg" +
                              "Ra2PuoBos8bFbIleb4trsgC6nl2tMv9vDKfXtvAhm74teHtaPRLjcI8UDUBkBWSLk6JjDWsDCbJfY/8Qsj7D" +
                              "EtZI6Nk8cy9KUcIJ9SsEyxSOaYNFsio1QmqjKQUScXiBj370TDlOr63iuRt/xS1u5Q41mnTf3FotISJZ6f7k" +
                              "sUy3J1QNgkrShjLtSM+cmAh9qpz4TMK+Vy9J/YD1l4WB43QaHOtlbbYu18j7JLQ58IQxnJXHn428eOx2nZN6" +
                              "o7CHd9uA="
            },
        };
            return tx;
        }

        public ValidationHelper GetValidationHelper()
        {
            return new ValidationHelper();
        }

        public IConsoleExtended GetConsole()
        {
            var consoleMock = new Mock<IConsoleExtended>();
            return consoleMock.Object;
        }
    }
}
