using CryptographyLib.Models;
using System.Text.Json;

namespace CryptographyLib.Helpers
{
    public static class TxParser
    {
        private const string OPERATION_KEY = "operation";
        private const string DECRYPTION_KEY = "decryption";
        private const string COMMISSION_DECRYPTION = "COMMISSION_DECRYPTION";
        private const string VOTING_BASE = "VOTING_BASE";
        private const string IS_ROLLBACK = "-1";

        private static readonly Dictionary<string, VotingOperation> Operation = new()
        {
            { "addMainKey", VotingOperation.AddMainKey },
            { "createContract", VotingOperation.CreateContract },
            { "startVoting", VotingOperation.StartVoting },
            { "finishVoting", VotingOperation.FinishVoting },
            { "decryption", VotingOperation.Decryption },
            { "commissionDecryption", VotingOperation.CommissionDecryption },
            { "results", VotingOperation.Results },
            { "blindSigIssue", VotingOperation.BlindSigIssue },
            { "vote", VotingOperation.Vote },
            { "addVotersList", VotingOperation.AddVotersList }
        };

        public static object ParseLine(string line, string contractId)
        {
            var fields = line.Split(';');
            var isRollback = fields.Length >= 12 && fields[(int)FieldsEnum.Rollback] == IS_ROLLBACK;
            var txId = fields[(int)FieldsEnum.NestedTxId];

            if (isRollback)
            {
                return new Rollback
                {
                    IsRollback = true,
                    TxId = txId,
                };
            }

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            var raw = JsonSerializer.Deserialize<List<JsonModel>>(fields[(int)FieldsEnum.Params], options);
            var parsed = MapDataEntry(raw);
            var diffRaw = JsonSerializer.Deserialize<IEnumerable<JsonModel>>(fields[(int)FieldsEnum.Diff], options);
            var diff = MapDataEntry(diffRaw);

            return new Tx
            {
                NestedTxId = fields[(int)FieldsEnum.NestedTxId],
                Type = int.Parse(fields[(int)FieldsEnum.Type]),
                Signature = fields[(int)FieldsEnum.Signature],
                Version = int.Parse(fields[(int)FieldsEnum.Version]),
                Ts = long.Parse(fields[(int)FieldsEnum.Ts]),
                SenderPublicKey = fields[(int)FieldsEnum.SenderPublicKey],
                Fee = int.Parse(fields[(int)FieldsEnum.Fee]),
                FeeAssetId = fields[(int)FieldsEnum.FeeAssetId],
                Params = parsed,
                Diff = diff,
                Raw = raw != null ? raw.ToArray() : Array.Empty<JsonModel>(),
                Operation = parsed.ContainsKey(OPERATION_KEY) ? Operation[(parsed[OPERATION_KEY] as string)!] : VotingOperation.CreateContract,
                Extra = JsonSerializer.Deserialize<JsonExtraModel>(fields[(int)FieldsEnum.Extra], options)!,
                ContractId = contractId,
                IsRollback = false
            };
        }

        private static Dictionary<string, object> MapDataEntry(IEnumerable<JsonModel>? models)
        {
            var result = new Dictionary<string, object>();

            if (models == null)
                return result;

            foreach (var model in models)
            {
                if (model.BoolValue != null)
                    result.Add(model.Key, model.BoolValue);
                else if (model.IntValue != null)
                    result.Add(model.Key, model.IntValue);
                else if (model.BinaryValue != null)
                    result.Add(model.Key, model.BinaryValue);
                else if (!string.IsNullOrEmpty(model.StringValue))
                    result.Add(model.Key, model.StringValue);
            }

            return result;
        }

        public static Dictionary<string, object> GetContractState(IEnumerable<Tx> txs)
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };

            var state = new Dictionary<string, object>();
            foreach (var tx in txs)
            {
                var diff = tx.Diff;
                var operation = tx.Operation;

                switch (operation)
                {
                    case VotingOperation.Decryption:
                    {
                        var key = diff.Keys.First();
                        diff[key] = tx.Params[DECRYPTION_KEY];
                        break;
                    }
                    case VotingOperation.CommissionDecryption:
                        diff[COMMISSION_DECRYPTION] = tx.Params[DECRYPTION_KEY];
                        break;
                }

                foreach (var pair in diff)
                {
                    if (state.ContainsKey(pair.Key))
                        state[pair.Key] = pair.Value;
                    else state.Add(pair.Key, pair.Value);
                }
            }

            foreach (var keyValuePair in state)
            {
                var key = keyValuePair.Key;
                var value = keyValuePair.Value;

                if (key == VOTING_BASE)
                {
                    state[key] = JsonSerializer.Deserialize<VotingBaseKeyModel>(value.ToString()!, options)!;
                }

                if (key == COMMISSION_DECRYPTION)
                {
                    var stringToDeserialize = "{\"Objects\":" + value + "}";
                    state[key] = JsonSerializer.Deserialize<CommissionDecryptionModel>(stringToDeserialize, options)!;
                }
            }

            return state;
        }
    }
}
