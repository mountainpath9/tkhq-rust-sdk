// This file is @generated by prost-build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PathFormat {
    Unspecified = 0,
    Bip32 = 1,
}
impl PathFormat {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PathFormat::Unspecified => "PATH_FORMAT_UNSPECIFIED",
            PathFormat::Bip32 => "PATH_FORMAT_BIP32",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PATH_FORMAT_UNSPECIFIED" => Some(Self::Unspecified),
            "PATH_FORMAT_BIP32" => Some(Self::Bip32),
            _ => None,
        }
    }
}
/// Cryptographic Curve used to generate a given Private Key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Curve {
    Unspecified = 0,
    Secp256k1 = 1,
    Ed25519 = 2,
}
impl Curve {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Curve::Unspecified => "CURVE_UNSPECIFIED",
            Curve::Secp256k1 => "CURVE_SECP256K1",
            Curve::Ed25519 => "CURVE_ED25519",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CURVE_UNSPECIFIED" => Some(Self::Unspecified),
            "CURVE_SECP256K1" => Some(Self::Secp256k1),
            "CURVE_ED25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AddressFormat {
    Unspecified = 0,
    /// 04<X_COORDINATE><Y_COORDINATE>
    Uncompressed = 1,
    /// 02 or 03, followed by the X coordinate
    Compressed = 2,
    Ethereum = 3,
    Solana = 4,
    Cosmos = 5,
    Tron = 6,
}
impl AddressFormat {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AddressFormat::Unspecified => "ADDRESS_FORMAT_UNSPECIFIED",
            AddressFormat::Uncompressed => "ADDRESS_FORMAT_UNCOMPRESSED",
            AddressFormat::Compressed => "ADDRESS_FORMAT_COMPRESSED",
            AddressFormat::Ethereum => "ADDRESS_FORMAT_ETHEREUM",
            AddressFormat::Solana => "ADDRESS_FORMAT_SOLANA",
            AddressFormat::Cosmos => "ADDRESS_FORMAT_COSMOS",
            AddressFormat::Tron => "ADDRESS_FORMAT_TRON",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ADDRESS_FORMAT_UNSPECIFIED" => Some(Self::Unspecified),
            "ADDRESS_FORMAT_UNCOMPRESSED" => Some(Self::Uncompressed),
            "ADDRESS_FORMAT_COMPRESSED" => Some(Self::Compressed),
            "ADDRESS_FORMAT_ETHEREUM" => Some(Self::Ethereum),
            "ADDRESS_FORMAT_SOLANA" => Some(Self::Solana),
            "ADDRESS_FORMAT_COSMOS" => Some(Self::Cosmos),
            "ADDRESS_FORMAT_TRON" => Some(Self::Tron),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HashFunction {
    Unspecified = 0,
    NoOp = 1,
    Sha256 = 2,
    Keccak256 = 3,
    NotApplicable = 4,
}
impl HashFunction {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            HashFunction::Unspecified => "HASH_FUNCTION_UNSPECIFIED",
            HashFunction::NoOp => "HASH_FUNCTION_NO_OP",
            HashFunction::Sha256 => "HASH_FUNCTION_SHA256",
            HashFunction::Keccak256 => "HASH_FUNCTION_KECCAK256",
            HashFunction::NotApplicable => "HASH_FUNCTION_NOT_APPLICABLE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "HASH_FUNCTION_UNSPECIFIED" => Some(Self::Unspecified),
            "HASH_FUNCTION_NO_OP" => Some(Self::NoOp),
            "HASH_FUNCTION_SHA256" => Some(Self::Sha256),
            "HASH_FUNCTION_KECCAK256" => Some(Self::Keccak256),
            "HASH_FUNCTION_NOT_APPLICABLE" => Some(Self::NotApplicable),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PayloadEncoding {
    /// Default value if payload encoding is not set explicitly
    Unspecified = 0,
    /// Payload is encoded in hexadecimal
    /// We accept 0x-prefixed or non-0x prefixed payloads.
    /// We accept any casing (uppercase, lowercase, or mixed)
    Hexadecimal = 1,
    /// Payload is encoded as utf-8 text
    /// Will be converted to bytes for signature with Rust's standard String.as_bytes()
    TextUtf8 = 2,
}
impl PayloadEncoding {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PayloadEncoding::Unspecified => "PAYLOAD_ENCODING_UNSPECIFIED",
            PayloadEncoding::Hexadecimal => "PAYLOAD_ENCODING_HEXADECIMAL",
            PayloadEncoding::TextUtf8 => "PAYLOAD_ENCODING_TEXT_UTF8",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PAYLOAD_ENCODING_UNSPECIFIED" => Some(Self::Unspecified),
            "PAYLOAD_ENCODING_HEXADECIMAL" => Some(Self::Hexadecimal),
            "PAYLOAD_ENCODING_TEXT_UTF8" => Some(Self::TextUtf8),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MnemonicLanguage {
    Unspecified = 0,
    English = 1,
    SimplifiedChinese = 2,
    TraditionalChinese = 3,
    Czech = 4,
    French = 5,
    Italian = 6,
    Japanese = 7,
    Korean = 8,
    Spanish = 9,
}
impl MnemonicLanguage {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            MnemonicLanguage::Unspecified => "MNEMONIC_LANGUAGE_UNSPECIFIED",
            MnemonicLanguage::English => "MNEMONIC_LANGUAGE_ENGLISH",
            MnemonicLanguage::SimplifiedChinese => "MNEMONIC_LANGUAGE_SIMPLIFIED_CHINESE",
            MnemonicLanguage::TraditionalChinese => "MNEMONIC_LANGUAGE_TRADITIONAL_CHINESE",
            MnemonicLanguage::Czech => "MNEMONIC_LANGUAGE_CZECH",
            MnemonicLanguage::French => "MNEMONIC_LANGUAGE_FRENCH",
            MnemonicLanguage::Italian => "MNEMONIC_LANGUAGE_ITALIAN",
            MnemonicLanguage::Japanese => "MNEMONIC_LANGUAGE_JAPANESE",
            MnemonicLanguage::Korean => "MNEMONIC_LANGUAGE_KOREAN",
            MnemonicLanguage::Spanish => "MNEMONIC_LANGUAGE_SPANISH",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "MNEMONIC_LANGUAGE_UNSPECIFIED" => Some(Self::Unspecified),
            "MNEMONIC_LANGUAGE_ENGLISH" => Some(Self::English),
            "MNEMONIC_LANGUAGE_SIMPLIFIED_CHINESE" => Some(Self::SimplifiedChinese),
            "MNEMONIC_LANGUAGE_TRADITIONAL_CHINESE" => Some(Self::TraditionalChinese),
            "MNEMONIC_LANGUAGE_CZECH" => Some(Self::Czech),
            "MNEMONIC_LANGUAGE_FRENCH" => Some(Self::French),
            "MNEMONIC_LANGUAGE_ITALIAN" => Some(Self::Italian),
            "MNEMONIC_LANGUAGE_JAPANESE" => Some(Self::Japanese),
            "MNEMONIC_LANGUAGE_KOREAN" => Some(Self::Korean),
            "MNEMONIC_LANGUAGE_SPANISH" => Some(Self::Spanish),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Effect {
    Unspecified = 0,
    Allow = 1,
    Deny = 2,
}
impl Effect {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Effect::Unspecified => "EFFECT_UNSPECIFIED",
            Effect::Allow => "EFFECT_ALLOW",
            Effect::Deny => "EFFECT_DENY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "EFFECT_UNSPECIFIED" => Some(Self::Unspecified),
            "EFFECT_ALLOW" => Some(Self::Allow),
            "EFFECT_DENY" => Some(Self::Deny),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AccessType {
    Unspecified = 0,
    Web = 1,
    Api = 2,
    All = 3,
}
impl AccessType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AccessType::Unspecified => "ACCESS_TYPE_UNSPECIFIED",
            AccessType::Web => "ACCESS_TYPE_WEB",
            AccessType::Api => "ACCESS_TYPE_API",
            AccessType::All => "ACCESS_TYPE_ALL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ACCESS_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "ACCESS_TYPE_WEB" => Some(Self::Web),
            "ACCESS_TYPE_API" => Some(Self::Api),
            "ACCESS_TYPE_ALL" => Some(Self::All),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CredentialType {
    Unspecified = 0,
    WebauthnAuthenticator = 1,
    ApiKeyP256 = 2,
    RecoverUserKeyP256 = 3,
}
impl CredentialType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CredentialType::Unspecified => "CREDENTIAL_TYPE_UNSPECIFIED",
            CredentialType::WebauthnAuthenticator => "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR",
            CredentialType::ApiKeyP256 => "CREDENTIAL_TYPE_API_KEY_P256",
            CredentialType::RecoverUserKeyP256 => "CREDENTIAL_TYPE_RECOVER_USER_KEY_P256",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CREDENTIAL_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "CREDENTIAL_TYPE_WEBAUTHN_AUTHENTICATOR" => Some(Self::WebauthnAuthenticator),
            "CREDENTIAL_TYPE_API_KEY_P256" => Some(Self::ApiKeyP256),
            "CREDENTIAL_TYPE_RECOVER_USER_KEY_P256" => Some(Self::RecoverUserKeyP256),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FeatureName {
    Unspecified = 0,
    /// to be deprecated in favor of rename: `FEATURE_NAME_EMAIL_RECOVERY`
    RootUserEmailRecovery = 1,
    WebauthnOrigins = 2,
    EmailAuth = 3,
    EmailRecovery = 4,
    Webhook = 5,
}
impl FeatureName {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            FeatureName::Unspecified => "FEATURE_NAME_UNSPECIFIED",
            FeatureName::RootUserEmailRecovery => "FEATURE_NAME_ROOT_USER_EMAIL_RECOVERY",
            FeatureName::WebauthnOrigins => "FEATURE_NAME_WEBAUTHN_ORIGINS",
            FeatureName::EmailAuth => "FEATURE_NAME_EMAIL_AUTH",
            FeatureName::EmailRecovery => "FEATURE_NAME_EMAIL_RECOVERY",
            FeatureName::Webhook => "FEATURE_NAME_WEBHOOK",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FEATURE_NAME_UNSPECIFIED" => Some(Self::Unspecified),
            "FEATURE_NAME_ROOT_USER_EMAIL_RECOVERY" => Some(Self::RootUserEmailRecovery),
            "FEATURE_NAME_WEBAUTHN_ORIGINS" => Some(Self::WebauthnOrigins),
            "FEATURE_NAME_EMAIL_AUTH" => Some(Self::EmailAuth),
            "FEATURE_NAME_EMAIL_RECOVERY" => Some(Self::EmailRecovery),
            "FEATURE_NAME_WEBHOOK" => Some(Self::Webhook),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TransactionType {
    Unspecified = 0,
    /// Unsigned Ethereum transaction, RLP-encoded and hex-encoded
    Ethereum = 1,
}
impl TransactionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            TransactionType::Unspecified => "TRANSACTION_TYPE_UNSPECIFIED",
            TransactionType::Ethereum => "TRANSACTION_TYPE_ETHEREUM",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "TRANSACTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "TRANSACTION_TYPE_ETHEREUM" => Some(Self::Ethereum),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Outcome {
    Unspecified = 0,
    Allow = 1,
    DenyExplicit = 2,
    DenyImplicit = 3,
    RequiresConsensus = 4,
    Rejected = 5,
}
impl Outcome {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Outcome::Unspecified => "OUTCOME_UNSPECIFIED",
            Outcome::Allow => "OUTCOME_ALLOW",
            Outcome::DenyExplicit => "OUTCOME_DENY_EXPLICIT",
            Outcome::DenyImplicit => "OUTCOME_DENY_IMPLICIT",
            Outcome::RequiresConsensus => "OUTCOME_REQUIRES_CONSENSUS",
            Outcome::Rejected => "OUTCOME_REJECTED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "OUTCOME_UNSPECIFIED" => Some(Self::Unspecified),
            "OUTCOME_ALLOW" => Some(Self::Allow),
            "OUTCOME_DENY_EXPLICIT" => Some(Self::DenyExplicit),
            "OUTCOME_DENY_IMPLICIT" => Some(Self::DenyImplicit),
            "OUTCOME_REQUIRES_CONSENSUS" => Some(Self::RequiresConsensus),
            "OUTCOME_REJECTED" => Some(Self::Rejected),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Operator {
    Unspecified = 0,
    Equal = 1,
    MoreThan = 2,
    MoreThanOrEqual = 3,
    LessThan = 4,
    LessThanOrEqual = 5,
    Contains = 6,
    NotEqual = 7,
    In = 8,
    NotIn = 9,
    ContainsOne = 10,
    ContainsAll = 11,
}
impl Operator {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Operator::Unspecified => "OPERATOR_UNSPECIFIED",
            Operator::Equal => "OPERATOR_EQUAL",
            Operator::MoreThan => "OPERATOR_MORE_THAN",
            Operator::MoreThanOrEqual => "OPERATOR_MORE_THAN_OR_EQUAL",
            Operator::LessThan => "OPERATOR_LESS_THAN",
            Operator::LessThanOrEqual => "OPERATOR_LESS_THAN_OR_EQUAL",
            Operator::Contains => "OPERATOR_CONTAINS",
            Operator::NotEqual => "OPERATOR_NOT_EQUAL",
            Operator::In => "OPERATOR_IN",
            Operator::NotIn => "OPERATOR_NOT_IN",
            Operator::ContainsOne => "OPERATOR_CONTAINS_ONE",
            Operator::ContainsAll => "OPERATOR_CONTAINS_ALL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "OPERATOR_UNSPECIFIED" => Some(Self::Unspecified),
            "OPERATOR_EQUAL" => Some(Self::Equal),
            "OPERATOR_MORE_THAN" => Some(Self::MoreThan),
            "OPERATOR_MORE_THAN_OR_EQUAL" => Some(Self::MoreThanOrEqual),
            "OPERATOR_LESS_THAN" => Some(Self::LessThan),
            "OPERATOR_LESS_THAN_OR_EQUAL" => Some(Self::LessThanOrEqual),
            "OPERATOR_CONTAINS" => Some(Self::Contains),
            "OPERATOR_NOT_EQUAL" => Some(Self::NotEqual),
            "OPERATOR_IN" => Some(Self::In),
            "OPERATOR_NOT_IN" => Some(Self::NotIn),
            "OPERATOR_CONTAINS_ONE" => Some(Self::ContainsOne),
            "OPERATOR_CONTAINS_ALL" => Some(Self::ContainsAll),
            _ => None,
        }
    }
}
