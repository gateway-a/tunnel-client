use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub server_addr: String,
    pub token: String,
    pub name: String,
    pub upstream_addr: String,
    #[serde(default = "default_reconnect")]
    pub reconnect_interval_sec: u64,
}

fn default_reconnect() -> u64 {
    3
}

impl AgentConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_config() {
        let yaml = r#"
server_addr: "127.0.0.1:9100"
token: "abc123"
name: "my-app"
upstream_addr: "127.0.0.1:3000"
"#;
        let config: AgentConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server_addr, "127.0.0.1:9100");
        assert_eq!(config.name, "my-app");
        assert_eq!(config.reconnect_interval_sec, 3);
    }
}
