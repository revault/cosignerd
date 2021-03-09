/// The logic to parse our static config (Noise keys, managers keys, ..)
pub mod config;

/// The logic to initiate our main state
pub mod cosignerd;

/// The database query and update logic
pub mod database;

/// Protocol message processing, we only have to handle a single message.
pub mod processing;

#[cfg(test)]
pub mod tests;
