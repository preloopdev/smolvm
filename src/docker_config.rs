//! Host-side Docker credential resolution.
//!
//! `docker login` stores registry credentials in `$DOCKER_CONFIG/config.json`
//! (default `~/.docker/config.json`), either inline under `auths` or, far more
//! commonly, behind a credential helper named by `credsStore` (Docker Desktop
//! writes `desktop`/`osxkeychain`; Linux installs use `pass` or
//! `secretservice`) or a per-registry `credHelpers` entry (`gcloud` for GCR).
//! A helper is a `docker-credential-<name>` executable that reads the registry
//! key on stdin and answers `get` with `{"Username":…,"Secret":…}`.
//!
//! Helpers only work where the login happened: mounting the config into the
//! guest hands crane a `credsStore` it cannot execute, which is why private
//! pulls with `--docker-config` failed on macOS. This module resolves the
//! credential on the HOST — the same lookup the Docker CLI performs — so it can
//! be forwarded to the guest as a plain username/secret pair.
//!
//! Resolution is fail-open: a missing or unreadable config, an absent helper,
//! or a helper that has nothing for the registry all yield `None`, and the
//! caller proceeds anonymously exactly as before.

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The config key Docker uses for Docker Hub in `auths` and `credHelpers`.
pub const DOCKER_HUB_KEY: &str = "https://index.docker.io/v1/";

/// Username a helper returns when the secret is an OAuth identity token rather
/// than a password.
pub const IDENTITY_TOKEN_USERNAME: &str = "<token>";

/// A credential resolved from the Docker config.
#[derive(Clone, PartialEq, Eq)]
pub struct DockerCredential {
    /// Registry username, or [`IDENTITY_TOKEN_USERNAME`] for an identity token.
    pub username: String,
    /// Password, personal access token, or identity token.
    pub secret: String,
}

impl DockerCredential {
    /// Whether `secret` is an OAuth identity token (username `<token>`).
    pub fn is_identity_token(&self) -> bool {
        self.username == IDENTITY_TOKEN_USERNAME
    }
}

impl std::fmt::Debug for DockerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerCredential")
            .field("username", &self.username)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// One `auths` entry of a Docker `config.json`.
#[derive(Debug, Default, Deserialize)]
struct AuthEntry {
    /// Base64 of `username:password`.
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    identitytoken: Option<String>,
}

/// The credential-bearing subset of a Docker `config.json`.
#[derive(Debug, Default, Deserialize)]
pub struct DockerConfig {
    #[serde(default)]
    auths: HashMap<String, AuthEntry>,
    #[serde(default, rename = "credsStore")]
    creds_store: Option<String>,
    #[serde(default, rename = "credHelpers")]
    cred_helpers: HashMap<String, String>,
}

/// Where a helper lookup ended.
enum HelperOutcome {
    Found(DockerCredential),
    NotFound,
    Failed(String),
}

impl DockerConfig {
    /// Parse a `config.json`. Any read or parse failure is `None`.
    pub fn load(path: &Path) -> Option<Self> {
        let contents = std::fs::read(path).ok()?;
        match serde_json::from_slice::<Self>(&contents) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "docker config.json did not parse");
                None
            }
        }
    }

    /// Parse from JSON text.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }

    /// The credential helper Docker would consult for `registry`, if any:
    /// a `credHelpers` entry for the registry key, else `credsStore`.
    pub fn helper_for(&self, registry: &str) -> Option<&str> {
        let key = server_key(registry);
        self.cred_helpers
            .get(key.as_str())
            .or(self.creds_store.as_ref())
            .map(String::as_str)
            .filter(|h| !h.is_empty())
    }

    /// Resolve a credential for `registry` the way the Docker CLI does: ask the
    /// helper first, then fall back to an inline `auths` entry.
    pub fn credential_for(&self, registry: &str) -> Option<DockerCredential> {
        self.credential_for_with(registry, run_helper)
    }

    fn credential_for_with(
        &self,
        registry: &str,
        run: impl Fn(&str, &str) -> HelperOutcome,
    ) -> Option<DockerCredential> {
        let key = server_key(registry);
        if let Some(helper) = self.helper_for(registry) {
            match run(helper, &key) {
                HelperOutcome::Found(cred) => {
                    tracing::debug!(
                        registry = %registry,
                        helper = %helper,
                        username = %cred.username,
                        "resolved registry credential via docker credential helper"
                    );
                    return Some(cred);
                }
                HelperOutcome::NotFound => {
                    tracing::debug!(registry = %registry, helper = %helper, "docker credential helper has no entry");
                }
                HelperOutcome::Failed(reason) => {
                    tracing::debug!(registry = %registry, helper = %helper, reason = %reason, "docker credential helper failed");
                }
            }
        }
        self.inline_credential(&key)
    }

    /// An `auths` entry for `key`, matched exactly or by hostname (Docker
    /// accepts `https://ghcr.io` and `ghcr.io/v1/` spellings for `ghcr.io`).
    fn inline_credential(&self, key: &str) -> Option<DockerCredential> {
        let entry = self.auths.get(key).or_else(|| {
            let host = hostname_of(key);
            self.auths
                .iter()
                .find(|(k, _)| hostname_of(k) == host)
                .map(|(_, v)| v)
        })?;
        if let Some(token) = entry.identitytoken.as_deref().filter(|t| !t.is_empty()) {
            return Some(DockerCredential {
                username: IDENTITY_TOKEN_USERNAME.to_string(),
                secret: token.to_string(),
            });
        }
        if let Some(auth) = entry.auth.as_deref().filter(|a| !a.is_empty()) {
            use base64::Engine as _;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(auth.trim())
                .ok()?;
            let decoded = String::from_utf8(decoded).ok()?;
            let (username, secret) = decoded.split_once(':')?;
            if username.is_empty() || secret.is_empty() {
                return None;
            }
            return Some(DockerCredential {
                username: username.to_string(),
                secret: secret.to_string(),
            });
        }
        match (entry.username.as_deref(), entry.password.as_deref()) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some(DockerCredential {
                username: u.to_string(),
                secret: p.to_string(),
            }),
            _ => None,
        }
    }
}

/// The key Docker files a registry under: Docker Hub's aliases collapse to
/// [`DOCKER_HUB_KEY`]; every other registry is keyed by its hostname.
pub fn server_key(registry: &str) -> String {
    match hostname_of(registry) {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" => DOCKER_HUB_KEY.to_string(),
        host => host.to_string(),
    }
}

/// Docker's `ConvertToHostname`: strip a scheme and any path.
fn hostname_of(key: &str) -> &str {
    let stripped = key
        .strip_prefix("https://")
        .or_else(|| key.strip_prefix("http://"))
        .unwrap_or(key);
    stripped.split('/').next().unwrap_or(stripped)
}

/// The Docker config file the CLI would read: `$DOCKER_CONFIG/config.json`,
/// else `~/.docker/config.json`.
pub fn config_path() -> Option<PathBuf> {
    crate::agent::docker_config_dir().map(|dir| dir.join("config.json"))
}

/// Resolve the host Docker credential for `registry` (`docker.io`, `ghcr.io`,
/// `localhost:5000`, …), or `None` when Docker has nothing usable for it.
pub fn credential_for(registry: &str) -> Option<DockerCredential> {
    let path = config_path()?;
    let config = DockerConfig::load(&path)?;
    config.credential_for(registry)
}

/// How long a helper may take to answer before it is killed and treated as
/// failed. A helper that blocks on a locked keychain or a GUI prompt would
/// otherwise hang the pull forever; the Docker CLI has been seen wedged on
/// `docker-credential-desktop get` for days.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(15);

/// Run `docker-credential-<helper> get` with `key` on stdin.
fn run_helper(helper: &str, key: &str) -> HelperOutcome {
    run_helper_with_timeout(helper, key, HELPER_TIMEOUT)
}

fn run_helper_with_timeout(helper: &str, key: &str, timeout: Duration) -> HelperOutcome {
    let program = format!("docker-credential-{helper}");
    let mut child = match Command::new(&program)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return HelperOutcome::Failed(format!("{program}: {e}")),
    };
    if let Some(mut stdin) = child.stdin.take() {
        // A helper that exits before reading stdin closes the pipe; that is
        // reported through its exit status, not this write.
        let _ = stdin.write_all(key.as_bytes());
    }
    // Poll rather than block: a reply is a few hundred bytes, far below the
    // pipe capacity, so reading after exit cannot deadlock.
    let deadline = Instant::now() + timeout;
    let mut wait = Duration::from_millis(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(wait);
                wait = (wait * 2).min(Duration::from_millis(100));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return HelperOutcome::Failed(format!(
                    "{program} did not answer within {}s",
                    timeout.as_secs()
                ));
            }
            Err(e) => return HelperOutcome::Failed(format!("{program}: {e}")),
        }
    }
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => return HelperOutcome::Failed(format!("{program}: {e}")),
    };
    parse_helper_output(
        &program,
        output.status.success(),
        &output.stdout,
        &output.stderr,
    )
}

/// Interpret a helper's `get` answer. A helper without an entry exits non-zero
/// and prints `credentials not found in native keychain`.
fn parse_helper_output(
    program: &str,
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> HelperOutcome {
    #[derive(Deserialize)]
    struct HelperReply {
        #[serde(rename = "Username", default)]
        username: String,
        #[serde(rename = "Secret", default)]
        secret: String,
    }
    let out = String::from_utf8_lossy(stdout);
    let err = String::from_utf8_lossy(stderr);
    if !success {
        let text = format!("{}{}", out.trim(), err.trim());
        if text.contains("credentials not found") {
            return HelperOutcome::NotFound;
        }
        let text = text.lines().next().unwrap_or("").trim().to_string();
        return HelperOutcome::Failed(format!("{program} exited with an error: {text}"));
    }
    match serde_json::from_str::<HelperReply>(out.trim()) {
        Ok(reply) if !reply.username.is_empty() && !reply.secret.is_empty() => {
            HelperOutcome::Found(DockerCredential {
                username: reply.username,
                secret: reply.secret,
            })
        }
        Ok(_) => HelperOutcome::NotFound,
        Err(e) => HelperOutcome::Failed(format!("{program} returned unparseable output: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape Docker Desktop on macOS writes: every credential behind the
    /// `desktop` store, GCR hosts routed to `gcloud`, `auths` entries empty.
    const DESKTOP_CONFIG: &str = r#"{
        "auths": {
            "128241912709.dkr.ecr.us-east-1.amazonaws.com": {},
            "https://index.docker.io/v1/": {},
            "registry.smolmachines.com": {}
        },
        "credsStore": "desktop",
        "credHelpers": {
            "asia.gcr.io": "gcloud",
            "gcr.io": "gcloud",
            "us-central1-docker.pkg.dev": "gcloud"
        },
        "currentContext": "desktop-linux",
        "plugins": { "-x-cli-hints": { "enabled": "true" } }
    }"#;

    fn found(username: &str, secret: &str) -> HelperOutcome {
        HelperOutcome::Found(DockerCredential {
            username: username.into(),
            secret: secret.into(),
        })
    }

    #[test]
    fn server_key_collapses_docker_hub_aliases() {
        for alias in [
            "docker.io",
            "index.docker.io",
            "registry-1.docker.io",
            "https://index.docker.io/v1/",
        ] {
            assert_eq!(server_key(alias), DOCKER_HUB_KEY, "{alias}");
        }
        assert_eq!(server_key("ghcr.io"), "ghcr.io");
        assert_eq!(server_key("https://ghcr.io"), "ghcr.io");
        assert_eq!(server_key("localhost:5000"), "localhost:5000");
    }

    #[test]
    fn desktop_config_routes_to_the_right_helper() {
        let config = DockerConfig::from_json(DESKTOP_CONFIG).unwrap();
        assert_eq!(config.helper_for("docker.io"), Some("desktop"));
        assert_eq!(
            config.helper_for("registry.smolmachines.com"),
            Some("desktop")
        );
        assert_eq!(
            config.helper_for("ghcr.io"),
            Some("desktop"),
            "credsStore covers unlisted hosts"
        );
        assert_eq!(config.helper_for("gcr.io"), Some("gcloud"));
        assert_eq!(
            config.helper_for("us-central1-docker.pkg.dev"),
            Some("gcloud")
        );
    }

    #[test]
    fn helper_is_asked_with_the_docker_key_and_wins() {
        let config = DockerConfig::from_json(DESKTOP_CONFIG).unwrap();
        let cred = config
            .credential_for_with("docker.io", |helper, key| {
                assert_eq!(helper, "desktop");
                assert_eq!(key, DOCKER_HUB_KEY);
                found("alice", "hunter2")
            })
            .expect("helper credential");
        assert_eq!(cred.username, "alice");
        assert_eq!(cred.secret, "hunter2");
        assert!(!cred.is_identity_token());
    }

    #[test]
    fn helper_miss_or_failure_is_none_when_nothing_is_inline() {
        let config = DockerConfig::from_json(DESKTOP_CONFIG).unwrap();
        assert!(config
            .credential_for_with("ghcr.io", |_, _| HelperOutcome::NotFound)
            .is_none());
        assert!(config
            .credential_for_with("ghcr.io", |_, _| HelperOutcome::Failed(
                "exec: not found".into()
            ))
            .is_none());
    }

    #[test]
    fn inline_auth_entry_is_used_when_no_helper_is_configured() {
        // base64("bob:s3cret")
        let config =
            DockerConfig::from_json(r#"{"auths":{"https://ghcr.io":{"auth":"Ym9iOnMzY3JldA=="}}}"#)
                .unwrap();
        assert_eq!(config.helper_for("ghcr.io"), None);
        let cred = config
            .credential_for_with("ghcr.io", |_, _| panic!("no helper configured"))
            .unwrap();
        assert_eq!(
            (cred.username.as_str(), cred.secret.as_str()),
            ("bob", "s3cret")
        );
    }

    #[test]
    fn inline_entry_is_the_fallback_after_a_helper_miss() {
        let config = DockerConfig::from_json(
            r#"{"credsStore":"desktop","auths":{"ghcr.io":{"username":"bob","password":"pw"}}}"#,
        )
        .unwrap();
        let cred = config
            .credential_for_with("ghcr.io", |_, _| HelperOutcome::NotFound)
            .unwrap();
        assert_eq!(
            (cred.username.as_str(), cred.secret.as_str()),
            ("bob", "pw")
        );
    }

    #[test]
    fn identity_token_entry_is_flagged() {
        let config = DockerConfig::from_json(
            r#"{"auths":{"https://index.docker.io/v1/":{"identitytoken":"idtok"}}}"#,
        )
        .unwrap();
        let cred = config
            .credential_for_with("docker.io", |_, _| HelperOutcome::NotFound)
            .unwrap();
        assert!(cred.is_identity_token());
        assert_eq!(cred.secret, "idtok");
    }

    #[test]
    fn empty_or_malformed_inline_entries_are_none() {
        let config = DockerConfig::from_json(
            r#"{"auths":{"a.io":{},"b.io":{"auth":"not-base64!"},"c.io":{"auth":"bm9jb2xvbg=="},"d.io":{"username":"x"}}}"#,
        )
        .unwrap();
        for host in ["a.io", "b.io", "c.io", "d.io", "missing.io"] {
            assert!(config.inline_credential(host).is_none(), "{host}");
        }
    }

    #[test]
    fn parse_helper_replies() {
        let ok = parse_helper_output(
            "h",
            true,
            br#"{"ServerURL":"ghcr.io","Username":"u","Secret":"s"}"#,
            b"",
        );
        assert!(matches!(ok, HelperOutcome::Found(c) if c.username == "u" && c.secret == "s"));
        let miss = parse_helper_output(
            "h",
            false,
            b"credentials not found in native keychain\n",
            b"",
        );
        assert!(matches!(miss, HelperOutcome::NotFound));
        let empty = parse_helper_output("h", true, br#"{"Username":"","Secret":""}"#, b"");
        assert!(matches!(empty, HelperOutcome::NotFound));
        let junk = parse_helper_output("h", true, b"<html>", b"");
        assert!(matches!(junk, HelperOutcome::Failed(_)));
        let crash = parse_helper_output("h", false, b"", b"panic: keychain locked\n");
        assert!(matches!(crash, HelperOutcome::Failed(m) if m.contains("keychain locked")));
    }

    #[cfg(unix)]
    #[test]
    fn real_helper_process_round_trip() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("docker-credential-smoltest");
        std::fs::write(
            &helper,
            "#!/bin/sh\nread key\ncase \"$key\" in\n  ghcr.io) printf '{\"ServerURL\":\"%s\",\"Username\":\"carol\",\"Secret\":\"tok\"}\\n' \"$key\" ;;\n  *) echo 'credentials not found in native keychain'; exit 1 ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![dir.path().to_path_buf()];
        paths.extend(std::env::split_paths(&old_path));
        let joined = std::env::join_paths(paths).unwrap();
        // Process-global; tests in this module that touch PATH stay in this one fn.
        std::env::set_var("PATH", &joined);
        let hit = run_helper("smoltest", "ghcr.io");
        let miss = run_helper("smoltest", DOCKER_HUB_KEY);
        let absent = run_helper("smoltest-does-not-exist", "ghcr.io");
        let hang = dir.path().join("docker-credential-smolhang");
        std::fs::write(&hang, "#!/bin/sh\nread key\nsleep 30\n").unwrap();
        std::fs::set_permissions(&hang, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = std::time::Instant::now();
        let hung = run_helper_with_timeout("smolhang", "ghcr.io", Duration::from_millis(300));
        let waited = started.elapsed();
        std::env::set_var("PATH", old_path);
        assert!(
            matches!(hung, HelperOutcome::Failed(ref m) if m.contains("did not answer")),
            "hung helper must fail open"
        );
        assert!(
            waited < Duration::from_secs(5),
            "hung helper must be killed at the timeout, waited {waited:?}"
        );
        assert!(
            matches!(hit, HelperOutcome::Found(c) if c.username == "carol" && c.secret == "tok")
        );
        assert!(matches!(miss, HelperOutcome::NotFound));
        assert!(
            matches!(absent, HelperOutcome::Failed(m) if m.contains("docker-credential-smoltest-does-not-exist"))
        );
    }

    #[test]
    fn missing_or_invalid_config_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(DockerConfig::load(&dir.path().join("config.json")).is_none());
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{not json").unwrap();
        assert!(DockerConfig::load(&bad).is_none());
    }

    #[test]
    fn debug_output_redacts_the_secret() {
        let cred = DockerCredential {
            username: "u".into(),
            secret: "very-secret".into(),
        };
        let shown = format!("{cred:?}");
        assert!(shown.contains("redacted") && !shown.contains("very-secret"));
    }
}
