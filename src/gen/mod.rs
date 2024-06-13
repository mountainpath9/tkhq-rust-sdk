// Unsure why prost-build doesn't generate file structure to match the module
// structure - hence this manual cruft

pub mod immutable {
    pub mod common {
        pub mod v1 {
            include!("immutable.common.v1.rs");
        }
    }
    pub mod activity {
        pub mod v1 {
            include!("immutable.activity.v1.rs");
        }
    }
    pub mod data {
        pub mod v1 {
            include!("immutable.data.v1.rs");
        }
    }
    pub mod webauthn {
        pub mod v1 {
            include!("immutable.webauthn.v1.rs");
        }
    }
}

pub mod external {
    pub mod options {
        pub mod v1 {
            include!("external.options.v1.rs");
        }
    }
    pub mod activity {
        pub mod v1 {
            include!("external.activity.v1.rs");
        }
    }
    pub mod data {
        pub mod v1 {
            include!("external.data.v1.rs");
        }
    }
    pub mod webauthn {
        pub mod v1 {
            include!("external.webauthn.v1.rs");
        }
    }
}

pub mod google {
    pub mod api {
        include!("google.api.rs");
    }
    pub mod rpc {
        include!("google.rpc.rs");
    }
}

pub mod services {
    pub mod coordinator {
        pub mod public {
            pub mod v1 {
                include!("services.coordinator.public.v1.rs");
            }
        }
    }
}
