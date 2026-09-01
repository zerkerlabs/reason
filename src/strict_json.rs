use std::str::FromStr;

use serde::{
    Deserialize,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};

/// Parse exactly one JSON value while rejecting duplicate object members at
/// every depth and fields ignored by the selected typed contract.
pub fn parse_strict_json<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = UniqueJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;

    let mut ignored = None;
    let parsed = serde_ignored::deserialize(value, |path| {
        if ignored.is_none() {
            ignored = Some(path.to_string());
        }
    })?;
    match ignored {
        None => Ok(parsed),
        Some(path) => Err(de::Error::custom(format!(
            "unknown object member at {path}"
        ))),
    }
}

/// Require every JSON number token to already equal serde_json's deterministic
/// representation. Without this check, accepted floating-point spellings can
/// silently round to another value before authorization commitments are made.
/// Call this only after JSON syntax has been validated by `parse_strict_json`.
pub fn validate_canonical_json_numbers(text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte != b'-' && !byte.is_ascii_digit() {
            index += 1;
            continue;
        }

        let start = index;
        index += 1;
        while index < bytes.len()
            && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        {
            index += 1;
        }
        let token = &text[start..index];
        let number = serde_json::Number::from_str(token)
            .map_err(|_| format!("invalid JSON number at byte {start}"))?;
        if number.to_string() != token {
            return Err(format!("non-canonical JSON number at byte {start}"));
        }
    }
    Ok(())
}

struct UniqueJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value with unique object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(UniqueJsonValue(serde_json::Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate object member `{key}`"
                )));
            }
            let value = map.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(serde_json::Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Outer {
        #[serde(rename = "inner")]
        _inner: Inner,
    }

    #[derive(Debug, Deserialize)]
    struct Inner {
        #[serde(rename = "value")]
        _value: bool,
    }

    #[test]
    fn rejects_duplicate_and_unknown_members_recursively() {
        let duplicate = r#"{"inner":{"value":true,"value":false}}"#;
        assert!(
            parse_strict_json::<Outer>(duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate object member `value`")
        );

        let unknown = r#"{"inner":{"value":true,"bypass":true}}"#;
        assert!(
            parse_strict_json::<Outer>(unknown)
                .unwrap_err()
                .to_string()
                .contains("unknown object member")
        );
    }

    #[test]
    fn canonical_number_validation_ignores_strings_and_rejects_lossy_tokens() {
        validate_canonical_json_numbers(
            r#"{"quoted":"-0 1e0 1.00","values":[0,0.0,-0.0,1.5,9007199254740993]}"#,
        )
        .unwrap();

        for token in [
            "-0",
            "1e0",
            "1.00",
            "0.10000000000000001",
            "9007199254740993.0",
        ] {
            let input = format!(r#"{{"value":{token}}}"#);
            assert!(
                validate_canonical_json_numbers(&input)
                    .unwrap_err()
                    .contains("non-canonical JSON number"),
                "accepted {token}"
            );
        }
    }
}
