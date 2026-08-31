use crate::Result;
use crate::txt_record::TTxtRecord;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PureRustTxtRecord {
    entries: HashMap<String, String>,
}

impl TTxtRecord for PureRustTxtRecord {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, key: &str, value: &str) -> Result<()> {
        if key.is_empty() || !key.is_ascii() || key.contains('=') {
            return Err("TXT record keys must be non-empty ASCII and may not contain '='".into());
        }
        if key.len() + 1 + value.len() > u8::MAX as usize {
            return Err("TXT record entry exceeds 255 bytes".into());
        }
        self.entries.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Option<String> {
        self.entries.get(key).cloned()
    }

    fn remove(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }

    fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = (String, String)> + 'a> {
        Box::new(
            self.entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }

    fn keys<'a>(&'a self) -> Box<dyn Iterator<Item = String> + 'a> {
        Box::new(self.entries.keys().cloned())
    }

    fn values<'a>(&'a self) -> Box<dyn Iterator<Item = String> + 'a> {
        Box::new(self.entries.values().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_entries() {
        let mut txt = PureRustTxtRecord::new();
        assert!(txt.insert("", "value").is_err());
        assert!(txt.insert("a=b", "value").is_err());
        assert!(txt.insert("key", &"x".repeat(252)).is_err());
    }
}
