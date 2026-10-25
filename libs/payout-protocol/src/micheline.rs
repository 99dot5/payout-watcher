//! Reading Micheline JSON, as a Tezos node renders it in block metadata and
//! contract scripts, by FIELD ANNOTATION rather than by position.
//!
//! The vault's events are emitted with their type (`with_type=True`), its
//! storage type is in its script, and the `fast_payout` parameter type is
//! fixed by the contract. Walking a value through its type and keeping the
//! `%field`-annotated leaves makes the reader independent of how the record
//! is laid out (SmartPy emits a right comb in alphabetical field order today)
//! and turns any shape surprise into a named error instead of a misread
//! amount.

use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Why a Micheline node could not be read as what was expected.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct MichelineError(pub String);

fn shape(message: impl Into<String>) -> MichelineError {
    MichelineError(message.into())
}

fn prim(node: &Value) -> Option<&str> {
    node.get("prim").and_then(Value::as_str)
}

fn args(node: &Value) -> &[Value] {
    node.get("args")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// The `%name` field annotation of a type node, if any.
fn field_annotation(ty: &Value) -> Option<&str> {
    ty.get("annots")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|a| a.strip_prefix('%'))
}

/// Split an n-ary `pair` type into its first component and the comb of the
/// rest (`pair a b c` is `pair a (pair b c)`).
fn split_pair_type(ty: &Value) -> Result<(Value, Value), MichelineError> {
    let parts = args(ty);
    match parts.len() {
        0 | 1 => Err(shape("a pair type with fewer than two components")),
        2 => Ok((parts[0].clone(), parts[1].clone())),
        _ => Ok((
            parts[0].clone(),
            serde_json::json!({ "prim": "pair", "args": parts[1..].to_vec() }),
        )),
    }
}

/// Split a pair VALUE the same way: `Pair a b c`, `Pair a (Pair b c)` and the
/// sequence form `[a, b, c]` the node may render a comb as are all accepted.
fn split_pair_value(value: &Value) -> Result<(Value, Value), MichelineError> {
    let parts: &[Value] = match value {
        Value::Array(items) => items.as_slice(),
        _ if prim(value) == Some("Pair") => args(value),
        _ => return Err(shape(format!("expected a Pair, found {value}"))),
    };
    match parts.len() {
        0 | 1 => Err(shape("a Pair with fewer than two components")),
        2 => Ok((parts[0].clone(), parts[1].clone())),
        _ => Ok((
            parts[0].clone(),
            serde_json::json!({ "prim": "Pair", "args": parts[1..].to_vec() }),
        )),
    }
}

/// Every `%field`-annotated node of `value`, read through its type `ty`.
pub fn fields(ty: &Value, value: &Value) -> Result<BTreeMap<String, Value>, MichelineError> {
    let mut out = BTreeMap::new();
    collect(ty, value, &mut out)?;

    Ok(out)
}

fn collect(
    ty: &Value,
    value: &Value,
    out: &mut BTreeMap<String, Value>,
) -> Result<(), MichelineError> {
    if let Some(name) = field_annotation(ty)
        && out.insert(name.to_string(), value.clone()).is_some()
    {
        return Err(shape(format!("field %{name} appears twice in the type")));
    }
    if prim(ty) == Some("pair") {
        let (ty_first, ty_rest) = split_pair_type(ty)?;
        let (first, rest) = split_pair_value(value)?;
        collect(&ty_first, &first, out)?;
        collect(&ty_rest, &rest, out)?;
    }

    Ok(())
}

/// The named field, or an error naming it.
pub fn field<'a>(
    fields: &'a BTreeMap<String, Value>,
    name: &str,
) -> Result<&'a Value, MichelineError> {
    fields
        .get(name)
        .ok_or_else(|| shape(format!("no %{name} field")))
}

/// An `int` node (a `mutez`, a `nat`) as a `u128`. Negative or non-numeric
/// text is refused: no amount in this protocol is negative.
pub fn as_u128(node: &Value) -> Result<u128, MichelineError> {
    let text = node
        .get("int")
        .and_then(Value::as_str)
        .ok_or_else(|| shape(format!("expected an int, found {node}")))?;

    text.parse::<u128>()
        .map_err(|_| shape(format!("'{text}' is not a non-negative integer")))
}

/// A `bytes` node.
pub fn as_bytes(node: &Value) -> Result<Vec<u8>, MichelineError> {
    let text = node
        .get("bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| shape(format!("expected bytes, found {node}")))?;

    hex::decode(text).map_err(|e| shape(format!("bytes are not hex: {e}")))
}

/// A `string` node.
pub fn as_string(node: &Value) -> Result<&str, MichelineError> {
    node.get("string")
        .and_then(Value::as_str)
        .ok_or_else(|| shape(format!("expected a string, found {node}")))
}

/// The elements of a `set` / `list` node.
pub fn as_sequence(node: &Value) -> Result<&[Value], MichelineError> {
    node.as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| shape(format!("expected a sequence, found {node}")))
}

/// The `(key, value)` entries of a `map` node.
pub fn as_map(node: &Value) -> Result<Vec<(&Value, &Value)>, MichelineError> {
    as_sequence(node)?
        .iter()
        .map(|elt| match (prim(elt), args(elt)) {
            (Some("Elt"), [k, v]) => Ok((k, v)),
            _ => Err(shape(format!("expected an Elt, found {elt}"))),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event_type() -> Value {
        // The compiled vault's `EMIT %fast_payout` type, verbatim.
        json!({"prim":"pair","args":[
            {"prim":"mutez","annots":["%fast"]},
            {"prim":"pair","args":[
                {"prim":"mutez","annots":["%paid_now"]},
                {"prim":"pair","args":[
                    {"prim":"mutez","annots":["%paid_total"]},
                    {"prim":"bytes","annots":["%session_id"]}]}]}]})
    }

    #[test]
    fn a_right_comb_record_is_read_by_annotation() {
        let value = json!({"prim":"Pair","args":[{"int":"5"},
            {"prim":"Pair","args":[{"int":"6"},{"prim":"Pair","args":[{"int":"7"},{"bytes":"aa"}]}]}]});
        let f = fields(&event_type(), &value).expect("decodes");

        assert_eq!(as_u128(field(&f, "fast").unwrap()), Ok(5));
        assert_eq!(as_u128(field(&f, "paid_now").unwrap()), Ok(6));
        assert_eq!(as_u128(field(&f, "paid_total").unwrap()), Ok(7));
        assert_eq!(as_bytes(field(&f, "session_id").unwrap()), Ok(vec![0xaa]));
    }

    #[test]
    fn the_flattened_and_sequence_comb_forms_read_the_same() {
        let flat =
            json!({"prim":"Pair","args":[{"int":"5"},{"int":"6"},{"int":"7"},{"bytes":"aa"}]});
        let seq = json!([{"int":"5"},{"int":"6"},{"int":"7"},{"bytes":"aa"}]);
        let nested = json!({"prim":"Pair","args":[{"int":"5"},
            {"prim":"Pair","args":[{"int":"6"},{"prim":"Pair","args":[{"int":"7"},{"bytes":"aa"}]}]}]});
        let n_ary_type = json!({"prim":"pair","args":[
            {"prim":"mutez","annots":["%fast"]},{"prim":"mutez","annots":["%paid_now"]},
            {"prim":"mutez","annots":["%paid_total"]},{"prim":"bytes","annots":["%session_id"]}]});
        let expected = fields(&event_type(), &nested).unwrap();

        assert_eq!(fields(&event_type(), &flat).unwrap(), expected);
        assert_eq!(fields(&event_type(), &seq).unwrap(), expected);
        assert_eq!(fields(&n_ary_type, &nested).unwrap(), expected);
    }

    #[test]
    fn a_value_that_does_not_fit_its_type_is_an_error_not_a_misread() {
        assert!(fields(&event_type(), &json!({"int":"5"})).is_err());
        assert!(as_u128(&json!({"int":"-1"})).is_err());
        assert!(as_u128(&json!({"bytes":"00"})).is_err());
        assert!(as_bytes(&json!({"bytes":"zz"})).is_err());
        assert!(as_map(&json!([{"prim":"Pair","args":[]}])).is_err());
    }
}
