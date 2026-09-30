use crlt::{Community, Db, params};

use super::{Storage, StoredPolicy, validate_transition};
use crate::{Error, MAX_DOCUMENT_BYTES, Result, identifier};

/// Append to the composition root's complete numbered migration history.
pub const SCHEMA: &str = "
CREATE TABLE cplc_policy (
    community_id TEXT NOT NULL,
    slot INTEGER NOT NULL CHECK (slot = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    document TEXT NOT NULL,
    PRIMARY KEY (community_id, slot)
) WITHOUT ROWID;
";

const SELECT: &str = "SELECT revision, document FROM cplc_policy WHERE slot = ?1";
const INSERT: &str = "INSERT INTO cplc_policy (slot, revision, document) VALUES (?1, ?2, ?3)";
const UPDATE: &str =
    "UPDATE cplc_policy SET revision = ?1, document = ?2 WHERE slot = ?3 AND revision = ?4";

/// Native libSQL storage through the shared crlt database facade.
#[derive(Clone)]
pub struct LibsqlStore {
    name: String,
    scope: Community,
}

impl LibsqlStore {
    /// Bind to an authorized community in an already migrated database.
    /// Deploy a separate physical database per community.
    pub fn new(db: &Db, community: impl Into<String>) -> Result<Self> {
        let name = community.into();
        identifier(&name)?;
        let scope = db.community(name.clone()).map_err(|_| Error::Storage)?;
        Ok(Self { name, scope })
    }

    /// Verify every SQL statement's query plan without changing data.
    pub async fn check_query_plans(&self) -> Result<()> {
        self.scope
            .explain(SELECT, [1i64])
            .await
            .map_err(|_| Error::Storage)?
            .assert_indexed()
            .map_err(|_| Error::Storage)?;
        self.scope
            .explain(INSERT, params![1i64, 1i64, "{}"])
            .await
            .map_err(|_| Error::Storage)?
            .assert_indexed()
            .map_err(|_| Error::Storage)?;
        self.scope
            .explain(UPDATE, params![2i64, "{}", 1i64, 1i64])
            .await
            .map_err(|_| Error::Storage)?
            .assert_indexed()
            .map_err(|_| Error::Storage)?;
        Ok(())
    }
}

fn decode(rows: &[crlt::Row], scope: &str) -> Result<Option<StoredPolicy>> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let document = row.get_str(1).map_err(|_| Error::Corrupt)?;
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::Corrupt);
    }
    let state: StoredPolicy = serde_json::from_str(document).map_err(|_| Error::Corrupt)?;
    state.validate().map_err(|_| Error::Corrupt)?;
    if state.community != scope
        || row.get_i64(0).map_err(|_| Error::Corrupt)? != state.revision as i64
    {
        return Err(Error::Corrupt);
    }
    Ok(Some(state))
}

impl Storage for LibsqlStore {
    fn community(&self) -> &str {
        &self.name
    }
    async fn load(&self) -> Result<Option<StoredPolicy>> {
        decode(
            &self
                .scope
                .query(SELECT, [1i64])
                .await
                .map_err(|_| Error::Storage)?,
            &self.name,
        )
    }
    async fn compare_exchange(&self, expected: Option<u64>, next: &StoredPolicy) -> Result<()> {
        let mut tx = self.scope.tx().await.map_err(|_| Error::Storage)?;
        let previous = decode(
            &tx.query(SELECT, [1i64]).await.map_err(|_| Error::Storage)?,
            &self.name,
        )?;
        validate_transition(&self.name, previous.as_ref(), expected, next)?;
        let document = serde_json::to_string(next).map_err(|_| Error::Corrupt)?;
        let count = match expected {
            None => {
                tx.execute(INSERT, params![1i64, next.revision as i64, document])
                    .await
            }
            Some(revision) => {
                tx.execute(
                    UPDATE,
                    params![next.revision as i64, document, 1i64, revision as i64],
                )
                .await
            }
        }
        .map_err(|_| Error::Storage)?;
        if count != 1 {
            return Err(Error::Conflict);
        }
        tx.commit().await.map_err(|_| Error::Storage)
    }
}
