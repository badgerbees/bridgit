use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde_json::Value;
use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

pub struct WebhookExporter {
    client: Client,
    endpoint: String,
    headers: BTreeMap<String, String>,
    max_retries: u32,
    backoff_ms: u64,
}

impl WebhookExporter {
    pub fn new(
        endpoint: String,
        headers: BTreeMap<String, String>,
        max_retries: u32,
        backoff_ms: u64,
    ) -> Result<Self> {
        Ok(Self {
            client: Client::builder().timeout(Duration::from_secs(15)).build()?,
            endpoint,
            headers,
            max_retries,
            backoff_ms,
        })
    }

    pub fn send(&self, record_id: &str, payload: &Value) -> Result<()> {
        let attempts = self.max_retries.saturating_add(1);
        for attempt in 0..attempts {
            let mut request = self
                .client
                .post(&self.endpoint)
                .header("X-Bridgit-Record-Id", record_id)
                .json(payload);
            for (name, value) in &self.headers {
                request = request.header(name, value);
            }
            match request.send() {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) if attempt + 1 == attempts => {
                    anyhow::bail!("webhook returned HTTP {}", response.status())
                }
                Ok(_) => {}
                Err(error) if attempt + 1 == attempts => {
                    return Err(error).context("sending webhook")
                }
                Err(_) => {}
            }
            thread::sleep(Duration::from_millis(
                self.backoff_ms.saturating_mul((attempt + 1) as u64),
            ));
        }
        unreachable!()
    }
}
