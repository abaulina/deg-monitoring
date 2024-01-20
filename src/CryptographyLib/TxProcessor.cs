using CryptographyLib.Helpers;
using CryptographyLib.Helpers.CryptoApi;
using CryptographyLib.Models;
using Newtonsoft.Json;
using System.Diagnostics;
using System.IO.Compression;

namespace CryptographyLib
{
    public class TxProcessor
    {
        private const string MAIN_KEY = "MAIN_KEY";
        private const string RESULTS = "RESULTS";
        private const string COMMISSION_DECRYPTION = "COMMISSION_DECRYPTION";
        private const string VOTING_BASE = "VOTING_BASE";
        private const string DECRYPTION_ = "DECRYPTION_";
        private const string COMMISSION_KEY = "COMMISSION_KEY";
        private const string DKG_KEY = "DKG_KEY";
        private const int CHUNK_SIZE = 64;
        private List<LogMessage> _messages;

        private bool _isBenchmark;
        private Stopwatch _stopWatchTxSignature;
        private Stopwatch _stopWatchBlindSignature;
        private Stopwatch _stopWatchZKP;
        private int _countTxSignature;
        private int _countBlindSignature;
        private int _countZKP;

        private readonly ValidationHelper _validationHelper;
        private CryptoProHelper _cryptoProHelper;

        public event EventHandler? MessagesChanged;


        public TxProcessor(bool isBenchmark = false)
        {
            _isBenchmark = isBenchmark;
            _stopWatchTxSignature = new Stopwatch();
            _stopWatchBlindSignature = new Stopwatch();
            _stopWatchZKP = new Stopwatch();
            _countTxSignature = 0;
            _countBlindSignature = 0;
            _countZKP = 0;

            _messages = new List<LogMessage>();
            _validationHelper = new ValidationHelper();
            _cryptoProHelper = new CryptoProHelper();
        }

        protected virtual void OnMessagesChanged(LogMessage lastMessage)
        {
            MessagesChanged?.Invoke(lastMessage, EventArgs.Empty);
        }

        private void AddMessageWithEvent(string message)
        {
            var logMessage = new LogMessage(message, LogMessageType.Info);
            _messages.Add(logMessage);
            OnMessagesChanged(logMessage);
        }
        private void AddBenchmarkMessageWithEvent(string message)
        {
            var benchmarkMessage = $"---BENCHMARK--- {message}";
            var logMessage = new LogMessage(benchmarkMessage, LogMessageType.Benchmark);
            _messages.Add(logMessage);

            OnMessagesChanged(logMessage);
        }
        private void AddErrorMessageWithEvent(string errorMessage)
        {
            var logMessage = new LogMessage(errorMessage, LogMessageType.Error);
            _messages.Add(logMessage);
            OnMessagesChanged(logMessage);
        }

        public async Task<IReadOnlyCollection<LogMessage>> GetMessages()
        {
            return _messages.ToList();
        }

        public IReadOnlyList<LogMessage> GetErrorMessages()
        {
            return _messages.Where(x => x.MessageType == LogMessageType.Benchmark).ToList();
        }

        public async Task ProcessTxFiles(string filesDirectory)
        {
            _messages = new List<LogMessage>();

            var contractIds = GetContractIds(filesDirectory);

            foreach (var contractId in contractIds)
            {
                var tmpPath = Path.Combine(Path.GetTempPath(), "deg-monitoring");
                if (Directory.Exists(tmpPath))
                    Directory.Delete(tmpPath, true);
                var tmpDir = Directory.CreateDirectory(tmpPath).FullName;
                try
                {
                    var files = Directory.EnumerateFiles(filesDirectory, $"{contractId}*.zip",
                        new EnumerationOptions { IgnoreInaccessible = true });

                    AddMessageWithEvent($"Проверка голосования {contractId}");
                    AddMessageWithEvent("Распаковка архивов...");

                    foreach (var file in files)
                    {
                        ZipFile.ExtractToDirectory(file, tmpDir);
                    }

                    AddMessageWithEvent("Обработка файлов с транзакциями");

                    await Validate(contractId, tmpDir);
                }
                catch (Exception ex)
                {
                    AddErrorMessageWithEvent(ex.Message);
                }

                if (_isBenchmark)
                {
                    AddBenchmarkMessageWithEvent($"Валидация подписей транзакций({_countTxSignature}): {_stopWatchTxSignature.ElapsedMilliseconds} мс");
                    AddBenchmarkMessageWithEvent($"Валидация слепых подписей транзакций({_countBlindSignature}): {_stopWatchBlindSignature.ElapsedMilliseconds} мс");
                    AddBenchmarkMessageWithEvent($"Валидация ZKP транзакций({_countZKP}): {_stopWatchZKP.ElapsedMilliseconds} мс");
                    _stopWatchBlindSignature.Reset();
                    _stopWatchTxSignature.Reset();
                    _stopWatchZKP.Reset();
                    _countTxSignature = 0;
                    _countBlindSignature = 0;
                    _countZKP = 0;

                }

                Directory.Delete(tmpDir, true);
            }
        }

        private HashSet<string> GetContractIds(string filesDirectory)
        {
            var contractIds = new HashSet<string>();
            var options = new EnumerationOptions { IgnoreInaccessible = true };
            var files = Directory.EnumerateFiles(filesDirectory, "*.zip", options);
            foreach (var file in files)
            {
                var contractId = Path.GetFileName(file).Split("_")[0];
                contractIds.Add(contractId);
            }

            return contractIds;
        }

        private async Task Validate(string contractId, string directory)
        {
            var files = Directory.EnumerateFiles(directory, "*.csv");

            var fileNames = files as string[] ?? files.ToArray();
            if (!fileNames.Any())
            {
                AddErrorMessageWithEvent("Файлы с транзакциями указанного голосования не найдены");
                return;
            }

            var stateTxs = new List<Tx>();
            var txsBuffer = new List<Tx>();
            var sum = new BulletinsSum { Valid = 0 };
            var rollbackTxs = new Dictionary<string, int>();

            var txNum = _cryptoProHelper.GetTotalTxCount(directory);
            var curIdx = 0;

            AddMessageWithEvent("Проверка служебных транзакций и роллбеков...");

            foreach (var fileName in fileNames)
            {
                var lines = File.ReadLines(fileName);
                foreach (var line in lines)
                {
                    var result = TxParser.ParseLine(line, contractId);
                    if (result is Rollback { IsRollback: true } rollbackResult)
                    {
                        if (rollbackTxs.ContainsKey(rollbackResult.TxId))
                        {
                            rollbackTxs[rollbackResult.TxId]++;
                        }
                        else
                        {
                            rollbackTxs.Add(rollbackResult.TxId, 1);
                        }
                    }
                }
            }


            foreach (var fileName in fileNames)
            {
                var lines = File.ReadLines(fileName);
                foreach (var line in lines)
                {
                    var result = TxParser.ParseLine(line, contractId);
                    if (result is Rollback { IsRollback: true })
                    {
                        continue;
                    }

                    var tx = result as Tx;
                    if (tx!.Operation != VotingOperation.BlindSigIssue && tx.Operation != VotingOperation.Vote)
                    {

                        if (_isBenchmark)
                        {
                            _stopWatchTxSignature.Start();
                        }

                        var txSignatureValidationResult = await _validationHelper.ValidateTxSignature(tx);

                        if (_isBenchmark)
                        {
                            _stopWatchTxSignature.Stop();
                            _countTxSignature++;
                        }

                        if (txSignatureValidationResult)
                        {
                            AddMessageWithEvent($"{tx.NestedTxId,44}: Подпись транзакции корректна");
                            stateTxs.Add(tx);
                        }
                        else
                        {
                            AddErrorMessageWithEvent($"{tx.NestedTxId,44}: Неверная подпись транзакции");
                        }

                        stateTxs.Add(tx);
                    }
                }
            }

            var contractState = TxParser.GetContractState(stateTxs);

            if (!contractState.ContainsKey(MAIN_KEY) || string.IsNullOrEmpty((string?)contractState[MAIN_KEY]))
            {
                AddErrorMessageWithEvent("Ошибка валидации голосования: не найден главный ключ");
            }

            if (!contractState.ContainsKey(VOTING_BASE))
            {
                AddErrorMessageWithEvent("Ошибка валидации голосования: не найдена конфигурация");
            }

            var mainKey = contractState[MAIN_KEY];
            var votingBaseObj = (VotingBaseKeyModel)contractState[VOTING_BASE];
            var dimension = votingBaseObj.Dimension;

            AddMessageWithEvent("Проверка бюллетеней...");

            foreach (var fileName in fileNames)
            {
                var lines = File.ReadLines(fileName);
                foreach (var line in lines)
                {
                    var result = TxParser.ParseLine(line, contractId);
                    curIdx++;
                    if (result is Rollback { IsRollback: true })
                    {
                        continue;
                    }

                    var tx = result as Tx;
                    if (tx!.Operation == VotingOperation.BlindSigIssue || tx.Operation == VotingOperation.Vote)
                    {
                        txsBuffer.Add(tx);
                        if (txsBuffer.Count > CHUNK_SIZE)
                        {
                            await ValidateAndSumVotersTxs(txsBuffer, rollbackTxs, contractState, (string)mainKey, dimension!, sum);
                        }
                    }

                    contractState = TxParser.GetContractState(stateTxs);
                }

                PrintProgress(curIdx, txNum);
            }

            await ValidateAndSumVotersTxs(txsBuffer, rollbackTxs, contractState, (string)mainKey, dimension!, sum);

            if (sum.Valid > 0)
            {
                await CheckSum(sum.Acc, contractState, sum.Valid);
            }

        }

        public async Task ValidateAndSumVotersTxs(List<Tx> txsBuffer, Dictionary<string, int> rollbackTxs,
           Dictionary<string, object> contractState, string mainKey, int[][] dimension, BulletinsSum sum)
        {
            var txs = new List<Tx>(txsBuffer.Take(CHUNK_SIZE));
            txsBuffer.RemoveRange(0, Math.Min(CHUNK_SIZE, txsBuffer.Count));

            var enumerable = txs.ToList();
            var promises = enumerable.Select(async tx =>
            {

                if (tx.Operation == VotingOperation.Vote)
                {
                    if (_isBenchmark)
                        _stopWatchBlindSignature.Start();

                    var validateBlindSignatureResult = _cryptoProHelper.ValidateBlindSignature(contractState, tx);

                    if (_isBenchmark)
                    {
                        _stopWatchBlindSignature.Stop();
                        _countBlindSignature++;
                    }

                    if (!validateBlindSignatureResult)
                    {
                        AddErrorMessageWithEvent($"{tx.NestedTxId,44}: Слепая подпись не прошла проверку");
                        return new ValidationResult
                        {
                            TxId = tx.NestedTxId,
                            Operation = tx.Operation,
                            Valid = false,
                        };
                    }

                    AddMessageWithEvent($"{tx.NestedTxId,44}: Слепая подпись корректна");

                    if (_isBenchmark)
                        _stopWatchZKP.Start();

                    var res = await _validationHelper.ValidateBulletin(tx, mainKey, dimension);

                    if (_isBenchmark)
                    {
                        _stopWatchZKP.Stop();
                        _countZKP++;
                    }
                    if (!res.Valid)
                    {
                        AddErrorMessageWithEvent($"{tx.NestedTxId.PadLeft(44, ' ') ?? ""}: Некорректный ZKP");
                    }
                    else
                    {
                        AddMessageWithEvent($"{tx.NestedTxId.PadLeft(44, ' ') ?? ""}: Проверка ZKP успешна");
                    }

                    return new ValidationResult
                    {
                        TxId = tx.NestedTxId,
                        Operation = tx.Operation,
                        Valid = res.Valid,
                    };
                }

                return new ValidationResult
                {
                    TxId = tx.NestedTxId,
                    Operation = tx.Operation,
                    Valid = true,
                };
            });

            var result = await Task.WhenAll(promises);

            var toSum = result
                .Where(r => r.Valid)
                .Where(r => r.Operation == VotingOperation.Vote)
                .Where(r => rollbackTxs.ContainsKey(r.TxId) ? !(rollbackTxs[r.TxId]-- == 1) : true)
                .Select(r => txs.First(t => t.NestedTxId == r.TxId))
                .Select(b => Convert.FromBase64String(b.Params["vote"] as string ?? throw new InvalidOperationException()))
                .Select(b => Bulletin.Decode(b))
                .Select(_cryptoProHelper.GetAbBytes).ToArray();

            if (toSum.Any())
            {
                sum.Valid += toSum.Length;

                if (sum.Acc != null)
                {
                    toSum = toSum.Append(sum.Acc.ToArray()).ToArray();
                }

                sum.Acc = await _validationHelper.AddVotesChunk(toSum, dimension.Select(d => d[2]).ToList());
            }
        }

        private Task CheckSum(AbBytes[][] sumABs, Dictionary<string, object> contractState, int validNum)
        {
            var votingBaseKeyModel = contractState[VOTING_BASE] as VotingBaseKeyModel;
            var dimension = votingBaseKeyModel!.Dimension![0].ToList();

            AddMessageWithEvent("Зашифрованная сумма подсчитана.");

            byte[]? masterPublicKey = null;
            Decryption[][]? masterDecryption = null;
            Decryption[][]? commissionDecryption = null;
            byte[]? commissionPublicKey = null;

            foreach (var entry in contractState)
            {
                var key = entry.Key;
                var value = entry.Value;

                if (key == DKG_KEY && value is string dkgKey)
                {
                    masterPublicKey = _cryptoProHelper.HexToByteArray(dkgKey);
                }
                else if (key == COMMISSION_KEY && value is string commissionKey)
                {
                    commissionPublicKey = _cryptoProHelper.HexToByteArray(commissionKey);
                }
                else if (key.StartsWith(DECRYPTION_) && value is string decryption)
                {
                    masterDecryption = JsonConvert.DeserializeObject<Decryption[][]>(decryption) ?? throw new ArgumentNullException(DECRYPTION_);
                }
                else if (key == COMMISSION_DECRYPTION && value is CommissionDecryptionModel commissionDecryptionModel)
                {
                    commissionDecryption = commissionDecryptionModel.Objects;
                }
            }

            AddMessageWithEvent($"Количество валидных бюллетеней: {validNum}");

            if (contractState.ContainsKey(RESULTS))
            {
                var results = JsonConvert.DeserializeObject<int[][]>(contractState[RESULTS].ToString()!);
                var sum = 0;

                if (results == null)
                {
                    throw new ArgumentNullException(nameof(results));
                }

                for (var i = 0; i < results.Length; i++)
                {
                    for (var j = 0; j < results[i].Length; j++)
                    {
                        sum += results[i][j];
                    }
                }
                AddMessageWithEvent($"Сумма из результатов: {JsonConvert.SerializeObject(sum)}");
            }
            else
            {
                AddMessageWithEvent($"Сумма не найдена среди данных транзакций");
            }

            if (masterDecryption != null && commissionDecryption != null && masterPublicKey != null && commissionPublicKey != null)
            {
                try
                {
                    _validationHelper.ValidateDecryption(sumABs, dimension, masterPublicKey, masterDecryption);
                    AddMessageWithEvent("Расшифровка сервера корректна.");
                }
                catch (Exception)
                {
                    throw new Exception("Расшифровка сервера некорректна.");
                }

                try
                {
                    _validationHelper.ValidateDecryption(sumABs, dimension, commissionPublicKey, commissionDecryption);
                    AddMessageWithEvent("Расшифровка комиссии корректна.");
                }
                catch (Exception)
                {
                    throw new Exception("Расшифровка комиссии некорректна.");
                }
            }
            else
            {
                throw new Exception("Не хватает данных для проверки расшифровок.");
            }

            AddMessageWithEvent("\nПодсчет результата...");
            var calculated = _validationHelper.CalculateResults(sumABs, dimension, validNum, masterPublicKey, masterDecryption, commissionPublicKey, commissionDecryption);

            var blockchainResults = JsonConvert.DeserializeObject<int[][]>(contractState[RESULTS].ToString() ?? throw new InvalidDataException(contractState[RESULTS].ToString()));
            AddMessageWithEvent($"Результат из блокчейна: {JsonConvert.SerializeObject(blockchainResults)}");
            AddMessageWithEvent($"Подсчитанный результат: {JsonConvert.SerializeObject(calculated)}");

            return Task.CompletedTask;
        }

        private void PrintProgress(int number, int total)
        {
            var percent = Math.Round((double)number / total * 100, 2);
            AddMessageWithEvent(Math.Abs(percent - total) < double.Epsilon
                ? $"Обработка транзакций: {percent}% завершено..."
                : $"    {percent}% завершено...");
        }
    }
}
