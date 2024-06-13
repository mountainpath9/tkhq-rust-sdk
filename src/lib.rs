pub mod client;
pub mod errors;

pub mod api {
    include!("gen/services.coordinator.public.v1.rs");
}

#[cfg(test)]
mod tests;
