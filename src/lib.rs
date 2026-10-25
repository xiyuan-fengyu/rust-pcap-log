pub mod config;
pub mod engine;
pub mod output;
pub mod packet;
mod rotation;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
