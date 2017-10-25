fn main() {
    // this is where I put copies of libunwind.so and
    // libunwind-ptrace.so retrieved from my Android device:
    println!("cargo:rustc-link-search=native=/home/dicej/Downloads");
}
