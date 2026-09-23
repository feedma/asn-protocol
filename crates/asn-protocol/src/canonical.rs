//! RFC 8785 canonical JSON.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

struct UnambiguousJson(serde_json::Value);

impl<'de> Deserialize<'de> for UnambiguousJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = UnambiguousJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unambiguous I-JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UnambiguousJson(value.into()))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UnambiguousJson(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UnambiguousJson(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(UnambiguousJson)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UnambiguousJson(value.into()))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(UnambiguousJson(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_none()
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UnambiguousJson>()? {
            values.push(value.0);
        }
        Ok(UnambiguousJson(values.into()))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = object.next_entry::<String, UnambiguousJson>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object member: {key}"
                )));
            }
        }
        Ok(UnambiguousJson(values.into()))
    }
}

/// Canonicalize an I-JSON document, rejecting duplicate object members.
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    let value: UnambiguousJson = serde_json::from_slice(input)?;
    serde_jcs::to_vec(&value.0)
}
