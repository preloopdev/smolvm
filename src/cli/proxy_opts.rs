//! Shared `--proxy` / `--no-proxy` flags for subcommands that pull images.
//!
//! Flatten this struct into a subcommand's `Args` derive to expose the flags
//! consistently. The values flow into `AgentRequest::Pull` and are set on
//! the `crane` subprocess as `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`.

use clap::Args;

#[derive(Args, Debug, Clone, Default)]
pub struct ProxyOpts {
    /// Proxy URL used for the in-VM image pull (sets HTTP_PROXY and HTTPS_PROXY
    /// on the registry client). Example: `http://192.168.127.254:3128`.
    #[arg(long, value_name = "URL", global = false)]
    pub proxy: Option<String>,

    /// Comma-separated NO_PROXY list of hosts/CIDRs that bypass the proxy
    /// during image pull. Example: `127.0.0.1,localhost,.internal`.
    #[arg(long, value_name = "LIST", global = false)]
    pub no_proxy: Option<String>,
}

impl ProxyOpts {
    /// Proxy URL for the in-VM image pull: the explicit `--proxy` flag, else the
    /// standard proxy environment variables (`HTTPS_PROXY`/`HTTP_PROXY`/
    /// `ALL_PROXY`, upper- or lower-case), so it works out of the box on a
    /// proxy-only network the way curl/docker/go do.
    pub fn proxy(&self) -> Option<String> {
        self.proxy.clone().or_else(|| {
            first_nonempty_env(&[
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ])
        })
    }

    /// NO_PROXY bypass list: the `--no-proxy` flag, else `NO_PROXY`/`no_proxy`.
    pub fn no_proxy(&self) -> Option<String> {
        self.no_proxy
            .clone()
            .or_else(|| first_nonempty_env(&["NO_PROXY", "no_proxy"]))
    }
}

/// First environment variable in `names` that is set to a non-empty value.
fn first_nonempty_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_fallback_picks_first_nonempty_in_order() {
        // Isolated names so the test never races real proxy vars.
        let a = "SMOLVM_TEST_PROXY_A_q7";
        let b = "SMOLVM_TEST_PROXY_B_q7";
        std::env::remove_var(a);
        std::env::remove_var(b);
        assert_eq!(first_nonempty_env(&[a, b]), None);
        std::env::set_var(b, "http://b:3128");
        assert_eq!(
            first_nonempty_env(&[a, b]).as_deref(),
            Some("http://b:3128")
        );
        // Whitespace-only is treated as unset; earlier-listed wins once real.
        std::env::set_var(a, "   ");
        assert_eq!(
            first_nonempty_env(&[a, b]).as_deref(),
            Some("http://b:3128")
        );
        std::env::set_var(a, "http://a:3128");
        assert_eq!(
            first_nonempty_env(&[a, b]).as_deref(),
            Some("http://a:3128")
        );
        std::env::remove_var(a);
        std::env::remove_var(b);
    }

    #[test]
    fn explicit_flag_wins_over_env() {
        let opts = ProxyOpts {
            proxy: Some("http://flag:3128".to_string()),
            no_proxy: Some("localhost".to_string()),
        };
        // The flag short-circuits before any env lookup.
        assert_eq!(opts.proxy().as_deref(), Some("http://flag:3128"));
        assert_eq!(opts.no_proxy().as_deref(), Some("localhost"));
    }
}
