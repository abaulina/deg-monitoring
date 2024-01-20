using System.ComponentModel;

namespace CryptographyLib.Models;

public enum FieldsEnum
{
    [Description("nestedTxId")]
    NestedTxId,

    [Description("type")]
    Type,

    [Description("signature")]
    Signature,

    [Description("version")]
    Version,

    [Description("ts")]
    Ts,

    [Description("senderPublicKey")]
    SenderPublicKey,

    [Description("fee")]
    Fee,

    [Description("feeAssetId")]
    FeeAssetId,

    [Description("params")]
    Params,

    [Description("diff")]
    Diff,

    [Description("extra")]
    Extra,

    [Description("rollback")]
    Rollback,
}