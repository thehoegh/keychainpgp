use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

use keychainpgp_core::types::TrustLevel;

use crate::error::{Error, Result};

/// A record representing a public key stored in the database.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// Primary key fingerprint (hex string).
    pub fingerprint: String,
    /// Primary User ID name.
    pub name: Option<String>,
    /// Primary User ID email.
    pub email: Option<String>,
    /// Key algorithm description.
    pub algorithm: String,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// Expiration timestamp (ISO 8601), if any.
    pub expires_at: Option<String>,
    /// Trust level.
    pub trust_level: i32,
    /// Whether this is the user's own key (has a corresponding private key).
    pub is_own_key: bool,
    /// Whether the key is revoked.
    pub is_revoked: bool,
    /// Local display alias. Independent of the OpenPGP User ID.
    pub alias: Option<String>,
    /// Raw ASCII-armored public key data.
    pub pgp_data: Vec<u8>,
}

const KEY_COLUMNS: &str = "fingerprint, name, email, algorithm, created_at, expires_at, trust_level, is_own_key, is_revoked, alias, pgp_data";

fn column_names(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(keys)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut names = Vec::new();
    for col in columns {
        names.push(col?);
    }
    Ok(names)
}

fn map_key_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRecord> {
    Ok(KeyRecord {
        fingerprint: row.get(0)?,
        name: row.get(1)?,
        email: row.get(2)?,
        algorithm: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        trust_level: row.get(6)?,
        is_own_key: row.get(7)?,
        is_revoked: row.get::<_, i32>(8)? != 0,
        alias: row.get(9)?,
        pgp_data: row.get(10)?,
    })
}

/// Normalize a local alias: trim, treat blank as absent, reject over 256 bytes.
fn normalize_alias(alias: Option<&str>) -> Result<Option<String>> {
    let Some(value) = alias else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 256 {
        return Err(Error::AliasTooLong);
    }
    Ok(Some(trimmed.to_string()))
}

/// SQLite-backed storage for public keys.
pub struct KeyStorage {
    conn: Connection,
}

impl KeyStorage {
    /// Open or create the key storage database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.initialize()?;
        Ok(storage)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.initialize()?;
        Ok(storage)
    }

    fn initialize(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS keys (
                fingerprint TEXT PRIMARY KEY NOT NULL,
                name        TEXT,
                email       TEXT,
                algorithm   TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT,
                trust_level INTEGER NOT NULL DEFAULT 0,
                is_own_key  INTEGER NOT NULL DEFAULT 0,
                is_revoked  INTEGER NOT NULL DEFAULT 0,
                alias       TEXT,
                pgp_data    BLOB NOT NULL
            );",
        )?;

        let columns = column_names(&self.conn)?;
        if !columns.iter().any(|c| c == "is_revoked") {
            self.conn.execute(
                "ALTER TABLE keys ADD COLUMN is_revoked INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !columns.iter().any(|c| c == "alias") {
            self.conn
                .execute("ALTER TABLE keys ADD COLUMN alias TEXT", [])?;
        }

        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_keys_email ON keys(email);
             CREATE INDEX IF NOT EXISTS idx_keys_name  ON keys(name);",
        )?;
        Ok(())
    }

    /// Insert a key record. Returns an error if the fingerprint already exists.
    pub fn insert(&self, record: &KeyRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO keys (fingerprint, name, email, algorithm, created_at, expires_at, trust_level, is_own_key, is_revoked, alias, pgp_data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.fingerprint,
                record.name,
                record.email,
                record.algorithm,
                record.created_at,
                record.expires_at,
                record.trust_level,
                record.is_own_key,
                record.is_revoked,
                record.alias,
                record.pgp_data,
            ],
        )?;
        Ok(())
    }

    /// Get a key record by fingerprint.
    pub fn get(&self, fingerprint: &str) -> Result<Option<KeyRecord>> {
        let record = self
            .conn
            .query_row(
                &format!("SELECT {KEY_COLUMNS} FROM keys WHERE fingerprint = ?1"),
                params![fingerprint],
                map_key_row,
            )
            .optional()?;
        Ok(record)
    }

    /// List all key records.
    pub fn list_all(&self) -> Result<Vec<KeyRecord>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM keys ORDER BY is_own_key DESC, name ASC"
        ))?;
        let records = stmt
            .query_map([], map_key_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Search keys by alias, name, email, or fingerprint (case-insensitive partial match).
    pub fn search(&self, query: &str) -> Result<Vec<KeyRecord>> {
        let pattern = format!("%{query}%");
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM keys
             WHERE alias LIKE ?1 COLLATE NOCASE
                OR name LIKE ?1 COLLATE NOCASE
                OR email LIKE ?1 COLLATE NOCASE
                OR fingerprint LIKE ?1 COLLATE NOCASE
             ORDER BY is_own_key DESC, name ASC"
        ))?;
        let records = stmt
            .query_map(params![pattern], map_key_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Delete a key by fingerprint.
    pub fn delete(&self, fingerprint: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM keys WHERE fingerprint = ?1",
            params![fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Mark a key as revoked.
    pub fn set_revoked(&self, fingerprint: &str, revoked: bool) -> Result<bool> {
        let rows = self.conn.execute(
            "UPDATE keys SET is_revoked = ?1 WHERE fingerprint = ?2",
            params![revoked as i32, fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Update the PGP data for a key.
    pub fn update_pgp_data(&self, fingerprint: &str, pgp_data: &[u8]) -> Result<bool> {
        let rows = self.conn.execute(
            "UPDATE keys SET pgp_data = ?1 WHERE fingerprint = ?2",
            params![pgp_data, fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Update the trust level for a key.
    pub fn set_trust(&self, fingerprint: &str, trust_level: TrustLevel) -> Result<bool> {
        let level: i32 = match trust_level {
            TrustLevel::Unknown => 0,
            TrustLevel::Unverified => 1,
            TrustLevel::Verified => 2,
        };
        let rows = self.conn.execute(
            "UPDATE keys SET trust_level = ?1 WHERE fingerprint = ?2",
            params![level, fingerprint],
        )?;
        Ok(rows > 0)
    }

    /// Set or clear the local alias. Blank input clears it. Returns false if the key is missing.
    pub fn set_alias(&self, fingerprint: &str, alias: Option<&str>) -> Result<bool> {
        let alias = normalize_alias(alias)?;
        let rows = self.conn.execute(
            "UPDATE keys SET alias = ?1 WHERE fingerprint = ?2",
            params![alias, fingerprint],
        )?;
        Ok(rows > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(fingerprint: &str, name: &str, email: &str) -> KeyRecord {
        KeyRecord {
            fingerprint: fingerprint.to_string(),
            name: Some(name.to_string()),
            email: Some(email.to_string()),
            algorithm: "Ed25519".to_string(),
            created_at: "2026-02-20T00:00:00Z".to_string(),
            expires_at: Some("2028-02-20T00:00:00Z".to_string()),
            trust_level: 0,
            is_own_key: false,
            is_revoked: false,
            alias: None,
            pgp_data: b"fake-pgp-data".to_vec(),
        }
    }

    #[test]
    fn test_insert_and_get() {
        let storage = KeyStorage::open_in_memory().unwrap();
        let record = make_record("AAAA1111", "Alice", "alice@example.com");
        storage.insert(&record).unwrap();

        let fetched = storage.get("AAAA1111").unwrap().unwrap();
        assert_eq!(fetched.name.as_deref(), Some("Alice"));
        assert_eq!(fetched.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn test_search_by_email() {
        let storage = KeyStorage::open_in_memory().unwrap();
        storage
            .insert(&make_record("AAAA", "Alice", "alice@example.com"))
            .unwrap();
        storage
            .insert(&make_record("BBBB", "Bob", "bob@example.com"))
            .unwrap();

        let results = storage.search("alice").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fingerprint, "AAAA");
    }

    #[test]
    fn test_delete() {
        let storage = KeyStorage::open_in_memory().unwrap();
        storage
            .insert(&make_record("AAAA", "Alice", "alice@example.com"))
            .unwrap();
        assert!(storage.delete("AAAA").unwrap());
        assert!(storage.get("AAAA").unwrap().is_none());
    }

    #[test]
    fn test_set_clear_and_search_alias() {
        let storage = KeyStorage::open_in_memory().unwrap();
        storage
            .insert(&make_record("AAAA", "Alice", "alice@example.com"))
            .unwrap();
        storage
            .insert(&make_record("BBBB", "Bob", "bob@example.com"))
            .unwrap();

        assert!(storage.set_alias("AAAA", Some("  Workbench  ")).unwrap());
        let fetched = storage.get("AAAA").unwrap().unwrap();
        assert_eq!(fetched.alias.as_deref(), Some("Workbench"));

        let results = storage.search("workbench").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fingerprint, "AAAA");

        assert!(storage.set_alias("AAAA", Some("   ")).unwrap());
        assert!(storage.get("AAAA").unwrap().unwrap().alias.is_none());
        assert!(storage.search("workbench").unwrap().is_empty());

        assert!(!storage.set_alias("MISSING", Some("Nope")).unwrap());
        assert!(storage.set_alias("AAAA", Some(&"x".repeat(257))).is_err());
    }

    #[test]
    fn test_migrate_adds_alias_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyring.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE keys (
                    fingerprint TEXT PRIMARY KEY NOT NULL,
                    name        TEXT,
                    email       TEXT,
                    algorithm   TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT,
                    trust_level INTEGER NOT NULL DEFAULT 0,
                    is_own_key  INTEGER NOT NULL DEFAULT 0,
                    is_revoked  INTEGER NOT NULL DEFAULT 0,
                    pgp_data    BLOB NOT NULL
                );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO keys (fingerprint, name, email, algorithm, created_at, trust_level, is_own_key, is_revoked, pgp_data)
                 VALUES ('AAAA', 'Alice', 'alice@example.com', 'Ed25519', '2026-02-20T00:00:00Z', 0, 0, 0, X'00')",
                [],
            )
            .unwrap();
        }

        let storage = KeyStorage::open(&path).unwrap();
        let fetched = storage.get("AAAA").unwrap().unwrap();
        assert!(fetched.alias.is_none());
        assert_eq!(fetched.name.as_deref(), Some("Alice"));
        assert!(storage.set_alias("AAAA", Some("Workbench")).unwrap());
        assert_eq!(
            storage.get("AAAA").unwrap().unwrap().alias.as_deref(),
            Some("Workbench")
        );
    }
}
