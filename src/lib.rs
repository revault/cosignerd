/// The logic to parse our static config (Noise keys, managers keys, ..)
pub mod config;

/// The logic to initiate our main state
pub mod cosignerd;

/// The database query and update logic
pub mod database;

/// Protocol message processing, we only have to handle a single message.
pub mod processing;

/// Unix daemon creation routine
pub mod daemonize;

#[cfg(any(test, feature = "fuzztesting"))]
pub mod tests;

#[cfg(feature = "fuzztesting")]
pub use {revault_net, revault_tx, serde, serde_json};
