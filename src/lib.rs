pub mod config;
pub mod engine;
pub mod output;
pub mod packet;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
