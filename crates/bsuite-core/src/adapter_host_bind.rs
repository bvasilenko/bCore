use crate::BsuiteCoreError;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

const HOST_CONTEXT_VARIANTS: &[&str] = &[
    "l2a",
    "payload-v3",
    "strapi-v5",
    "sanity-v3",
    "directus-v10",
];

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum HostContext {
    L2a,
    PayloadV3,
    StrapiV5,
    SanityV3,
    DirectusV10,
}

impl HostContext {
    pub const ALL: [Self; 5] = [
        Self::L2a,
        Self::PayloadV3,
        Self::StrapiV5,
        Self::SanityV3,
        Self::DirectusV10,
    ];

    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::L2a => "l2a",
            Self::PayloadV3 => "payload-v3",
            Self::StrapiV5 => "strapi-v5",
            Self::SanityV3 => "sanity-v3",
            Self::DirectusV10 => "directus-v10",
        }
    }

    pub fn from_stable_name(value: &str) -> Option<Self> {
        match value {
            "l2a" => Some(Self::L2a),
            "payload-v3" => Some(Self::PayloadV3),
            "strapi-v5" => Some(Self::StrapiV5),
            "sanity-v3" => Some(Self::SanityV3),
            "directus-v10" => Some(Self::DirectusV10),
            _ => None,
        }
    }
}

impl fmt::Display for HostContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_name())
    }
}

impl Serialize for HostContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.stable_name())
    }
}

impl<'de> Deserialize<'de> for HostContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_stable_name(&value)
            .ok_or_else(|| de::Error::unknown_variant(&value, HOST_CONTEXT_VARIANTS))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AdapterBinding {
    pub host: HostContext,
    pub package_name: String,
}

impl AdapterBinding {
    pub fn new(host: HostContext, package_name: impl Into<String>) -> Self {
        Self {
            host,
            package_name: package_name.into(),
        }
    }
}

pub trait AdapterHostBinder {
    fn bind(&self, host: HostContext) -> Result<AdapterBinding, BsuiteCoreError>;
}
