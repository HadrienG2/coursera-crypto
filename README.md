# An highly insecure implementation of various crypto primitives

These are Rust implementation of various crypto primitives that I wrote as part
of following the Coursera crypto MOOC.

These implementations do not take any precaution to be secure against side-
channel attacks. They does not zero out freed memory, ensure that operations on
secret data take constant time, protect secret data from being swapped out by
the underlying operating system, account for cache/power attacks, and so on.

As such, they should only be viewed as a learning exercise, and not as something
that you should use for your actual crypto needs.

If you would like to know more about how to implement cryptographic algorithms
securely and why it matters, here are some nice resources:

* [Coding rules for crypto code](https://cryptocoding.net/index.php/Coding_rules),
  and [associated references](https://cryptocoding.net/index.php/References)
* [More about constant-time algorithms](https://www.bearssl.org/constanttime.html)
* [Thoughts on Rust cryptography](https://speakerdeck.com/tarcieri/thoughts-on-rust-cryptography) (and
  [a discussion](https://www.reddit.com/r/rust/comments/4d8hxm/what_crypto_library_do_yall_use/)
  involving the author about the state of Rust crypto libraries in 2016)
