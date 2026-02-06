pub mod orchard;
pub mod errors;

// The following function is only necessary for the header generation.
#[cfg(feature = "headers")]
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("include/rust_points.h")?
        .generate()
}