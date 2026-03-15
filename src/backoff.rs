use rand::Rng;
use std::time::Duration;

pub struct ExponentialBackoff {
    base_delay_ms: u64,
    max_delay_ms: u64,
    attempt: u32,
    jitter_percent: f64,
}

impl ExponentialBackoff {
    pub fn new() -> Self {
        Self {
            base_delay_ms: 1000,
            max_delay_ms: 60_000,
            attempt: 0,
            jitter_percent: 0.2,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let base_delay = self.base_delay_ms * 2_u64.pow(self.attempt);
        let capped = base_delay.min(self.max_delay_ms);

        let jitter = if self.jitter_percent > 0.0 {
            let mut rng = rand::thread_rng();
            let variation = (capped as f64) * self.jitter_percent;
            rng.gen_range(-variation..=variation) as i64
        } else {
            0
        };

        let final_delay = (capped as i64 + jitter).max(0) as u64;
        self.attempt += 1;

        Duration::from_millis(final_delay)
    }

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    #[allow(dead_code)]
    pub fn current_attempt(&self) -> u32 {
        self.attempt
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new()
    }
}
