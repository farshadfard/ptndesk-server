// Customer-lock allowlist for hbbs.
//
// Two independent features, each OFF unless its env var is set. With neither set
// the server behaves exactly like upstream.
//
//   ALLOWLIST_DB=/var/lib/rustdesk/allowlist.sqlite3
//       Only RustDesk IDs present (and unexpired) in the `allowed_peer` table may
//       register or be connected to. Unknown IDs are dropped.
//
//   PUNCH_ALLOW_IPS=1.2.3.4,10.8.0.0/24
//       Only these source IPs may send punch-hole / relay requests (support
//       staff). Customers never send them, so nothing breaks for customers.
//
// The sqlite file is owned/written by an external service (the allow-writer
// sidecar); hbbs only ever opens it read-only. Schema:
//
//   CREATE TABLE allowed_peer (
//     id            TEXT PRIMARY KEY,
//     customer_code INTEGER NOT NULL,
//     role          TEXT NOT NULL DEFAULT 'customer',
//     expires_at    INTEGER            -- unix seconds, NULL = never
//   );

use hbb_common::{log, tokio::sync::Mutex};
use ipnetwork::IpNetwork;
use once_cell::sync::Lazy;
use sqlx::{sqlite::SqliteConnectOptions, Connection, SqliteConnection};
use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    time::{Duration, Instant},
};

const POSITIVE_TTL: Duration = Duration::from_secs(300);
// Negative TTL is short: a client registers within seconds of being verified.
const NEGATIVE_TTL: Duration = Duration::from_secs(10);

// `None` => feature off. Evaluated once, lazily, after init_args() has run.
static DB_URL: Lazy<Option<String>> = Lazy::new(|| {
    let v = crate::common::get_arg("ALLOWLIST_DB");
    if v.trim().is_empty() {
        None
    } else {
        log::info!("registration allowlist enabled: {}", v);
        Some(v)
    }
});

static CACHE: Lazy<Mutex<HashMap<String, (bool, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Whether `id` may register / be connected to. Always true when the allowlist
/// feature is off (`ALLOWLIST_DB` unset). Fails closed (denies) on any DB error.
pub async fn is_allowed(id: &str) -> bool {
    let url = match DB_URL.as_ref() {
        Some(u) => u,
        None => return true,
    };
    {
        let cache = CACHE.lock().await;
        if let Some((val, tm)) = cache.get(id) {
            let ttl = if *val { POSITIVE_TTL } else { NEGATIVE_TTL };
            if tm.elapsed() < ttl {
                return *val;
            }
        }
    }
    let allowed = match query(url, id).await {
        Ok(v) => v,
        Err(e) => {
            log::error!("allowlist query failed ({}): {}", url, e);
            false // fail closed
        }
    };
    CACHE
        .lock()
        .await
        .insert(id.to_owned(), (allowed, Instant::now()));
    allowed
}

async fn query(url: &str, id: &str) -> Result<bool, sqlx::Error> {
    let opt = SqliteConnectOptions::from_str(url)?
        .read_only(true)
        .pragma("busy_timeout", "2000");
    let mut conn = SqliteConnection::connect_with(&opt).await?;
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM allowed_peer \
         WHERE id = ?1 AND (expires_at IS NULL OR expires_at > strftime('%s','now')) \
         LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut conn)
    .await;
    let _ = conn.close().await;
    Ok(row?.is_some())
}

/// Clear the positive/negative cache so a revocation takes effect immediately
/// (called by the loopback `allow-flush` command) instead of after the TTL.
pub async fn flush_cache() {
    CACHE.lock().await.clear();
}

// ---- staff-only punch/relay source-IP restriction ----

static PUNCH_ALLOW_IPS: Lazy<Option<Vec<IpNetwork>>> = Lazy::new(|| {
    let raw = crate::common::get_arg("PUNCH_ALLOW_IPS");
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let nets: Vec<IpNetwork> = raw.split(',').filter_map(parse_net).collect();
    if nets.is_empty() {
        log::warn!("PUNCH_ALLOW_IPS set but no valid entries parsed; restriction stays off");
        None
    } else {
        log::info!("staff-only punch/relay enabled: {} network(s)", nets.len());
        Some(nets)
    }
});

fn parse_net(s: &str) -> Option<IpNetwork> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<IpNetwork>() {
        return Some(n);
    }
    match s.parse::<IpAddr>() {
        Ok(ip) => IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok(),
        Err(_) => None,
    }
}

/// Whether `ip` may send punch-hole / relay requests. Always true when
/// `PUNCH_ALLOW_IPS` is unset.
pub fn is_staff_ip(ip: IpAddr) -> bool {
    match PUNCH_ALLOW_IPS.as_ref() {
        None => true,
        Some(nets) => nets.iter().any(|n| n.contains(ip)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_net_accepts_ip_and_cidr_rejects_junk() {
        assert!(parse_net("1.2.3.4").is_some());
        assert!(parse_net("10.8.0.0/24").is_some());
        assert!(parse_net(" ").is_none());
        assert!(parse_net("not-an-ip").is_none());
    }

    #[test]
    fn cidr_contains_matches_only_inside_range() {
        let net = parse_net("10.8.0.0/24").unwrap();
        assert!(net.contains("10.8.0.5".parse::<IpAddr>().unwrap()));
        assert!(!net.contains("10.8.1.5".parse::<IpAddr>().unwrap()));
    }
}
