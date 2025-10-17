//! A small, self-contained SHA256, HMAC-SHA256, and HKDF-SHA256 implementation
//! (C) Frank Denis <fdenis [at] fastly [dot] com>
//!
//! This library provides a lightweight implementation of SHA-256, HMAC-SHA256, and HKDF-SHA256
//! cryptographic functions with no external dependencies (unless the `traits` feature is enabled).
//!
//! # Features
//!
//! - `traits`: Enables support for the `Digest` trait from the `digest` crate
//! - `opt_size`: Enables size optimizations (reduces `.text` section size by ~75% with ~16% performance cost)
//!
//! # Examples
//!
//! ```
//! // Calculate a SHA-256 hash
//! let hash = hmac_sha256::Hash::hash(b"hello world");
//!
//! // Verify a hash in one shot
//! let expected = hmac_sha256::Hash::hash(b"hello world");
//! assert!(hmac_sha256::Hash::verify(b"hello world", &expected));
//!
//! // Create an HMAC-SHA256
//! let mac = hmac_sha256::HMAC::mac(b"message", b"key");
//!
//! // Verify an HMAC-SHA256 in one shot
//! let expected = hmac_sha256::HMAC::mac(b"message", b"key");
//! assert!(hmac_sha256::HMAC::verify(b"message", b"key", &expected));
//!
//! // Use HKDF-SHA256 for key derivation
//! let prk = hmac_sha256::HKDF::extract(b"salt", b"input key material");
//! let mut output = [0u8; 32];
//! hmac_sha256::HKDF::expand(&mut output, prk, b"context info");
//! ```

#![allow(
    non_snake_case,
    clippy::cast_lossless,
    clippy::eq_op,
    clippy::identity_op,
    clippy::many_single_char_names,
    clippy::unreadable_literal
)]

#[inline(always)]
fn load_be(base: &[u8], offset: usize) -> u32 {
    let addr = &base[offset..];
    (addr[3] as u32) | (addr[2] as u32) << 8 | (addr[1] as u32) << 16 | (addr[0] as u32) << 24
}

#[inline(always)]
fn store_be(base: &mut [u8], offset: usize, x: u32) {
    let addr = &mut base[offset..];
    addr[3] = x as u8;
    addr[2] = (x >> 8) as u8;
    addr[1] = (x >> 16) as u8;
    addr[0] = (x >> 24) as u8;
}

fn verify(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false;
    }
    let mut v: u32 = 0;

    {
        let (mut h1, mut h2) = (0u32, 0u32);
        for (b1, b2) in x.iter().zip(y.iter()) {
            h1 ^= (h1 << 5).wrapping_add((h1 >> 2) ^ *b1 as u32);
            h2 ^= (h2 << 5).wrapping_add((h2 >> 2) ^ *b2 as u32);
        }
        v |= h1 ^ h2;
    }
    for (a, b) in x.iter().zip(y.iter()) {
        v |= (a ^ b) as u32;
    }
    let v = unsafe { core::ptr::read_volatile(&v) };
    v == 0
}

struct W([u32; 16]);

#[derive(Copy, Clone)]
struct State([u32; 8]);

impl W {
    fn new(input: &[u8]) -> Self {
        let mut w = [0u32; 16];
        for (i, e) in w.iter_mut().enumerate() {
            *e = load_be(input, i * 4)
        }
        W(w)
    }

    #[inline(always)]
    fn Ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn Maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn Sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn Sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn M(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let w = &mut self.0;
        w[a] = w[a]
            .wrapping_add(Self::sigma1(w[b]))
            .wrapping_add(w[c])
            .wrapping_add(Self::sigma0(w[d]));
    }

    #[inline]
    fn expand(&mut self) {
        self.M(0, (0 + 14) & 15, (0 + 9) & 15, (0 + 1) & 15);
        self.M(1, (1 + 14) & 15, (1 + 9) & 15, (1 + 1) & 15);
        self.M(2, (2 + 14) & 15, (2 + 9) & 15, (2 + 1) & 15);
        self.M(3, (3 + 14) & 15, (3 + 9) & 15, (3 + 1) & 15);
        self.M(4, (4 + 14) & 15, (4 + 9) & 15, (4 + 1) & 15);
        self.M(5, (5 + 14) & 15, (5 + 9) & 15, (5 + 1) & 15);
        self.M(6, (6 + 14) & 15, (6 + 9) & 15, (6 + 1) & 15);
        self.M(7, (7 + 14) & 15, (7 + 9) & 15, (7 + 1) & 15);
        self.M(8, (8 + 14) & 15, (8 + 9) & 15, (8 + 1) & 15);
        self.M(9, (9 + 14) & 15, (9 + 9) & 15, (9 + 1) & 15);
        self.M(10, (10 + 14) & 15, (10 + 9) & 15, (10 + 1) & 15);
        self.M(11, (11 + 14) & 15, (11 + 9) & 15, (11 + 1) & 15);
        self.M(12, (12 + 14) & 15, (12 + 9) & 15, (12 + 1) & 15);
        self.M(13, (13 + 14) & 15, (13 + 9) & 15, (13 + 1) & 15);
        self.M(14, (14 + 14) & 15, (14 + 9) & 15, (14 + 1) & 15);
        self.M(15, (15 + 14) & 15, (15 + 9) & 15, (15 + 1) & 15);
    }

    fn F(&mut self, state: &mut State, i: usize, k: u32) {
        let t = &mut state.0;
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma1(t[(16 - i + 4) & 7]))
            .wrapping_add(Self::Ch(
                t[(16 - i + 4) & 7],
                t[(16 - i + 5) & 7],
                t[(16 - i + 6) & 7],
            ))
            .wrapping_add(k)
            .wrapping_add(self.0[i]);
        t[(16 - i + 3) & 7] = t[(16 - i + 3) & 7].wrapping_add(t[(16 - i + 7) & 7]);
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma0(t[(16 - i + 0) & 7]))
            .wrapping_add(Self::Maj(
                t[(16 - i + 0) & 7],
                t[(16 - i + 1) & 7],
                t[(16 - i + 2) & 7],
            ));
    }

    fn G(&mut self, state: &mut State, s: usize) {
        const ROUND_CONSTANTS: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let rc = &ROUND_CONSTANTS[s * 16..];
        self.F(state, 0, rc[0]);
        self.F(state, 1, rc[1]);
        self.F(state, 2, rc[2]);
        self.F(state, 3, rc[3]);
        self.F(state, 4, rc[4]);
        self.F(state, 5, rc[5]);
        self.F(state, 6, rc[6]);
        self.F(state, 7, rc[7]);
        self.F(state, 8, rc[8]);
        self.F(state, 9, rc[9]);
        self.F(state, 10, rc[10]);
        self.F(state, 11, rc[11]);
        self.F(state, 12, rc[12]);
        self.F(state, 13, rc[13]);
        self.F(state, 14, rc[14]);
        self.F(state, 15, rc[15]);
    }
}

impl State {
    fn new() -> Self {
        const IV: [u8; 32] = [
            0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
            0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab,
            0x5b, 0xe0, 0xcd, 0x19,
        ];
        let mut t = [0u32; 8];
        for (i, e) in t.iter_mut().enumerate() {
            *e = load_be(&IV, i * 4)
        }
        State(t)
    }

    #[inline(always)]
    fn add(&mut self, x: &State) {
        let sx = &mut self.0;
        let ex = &x.0;
        sx[0] = sx[0].wrapping_add(ex[0]);
        sx[1] = sx[1].wrapping_add(ex[1]);
        sx[2] = sx[2].wrapping_add(ex[2]);
        sx[3] = sx[3].wrapping_add(ex[3]);
        sx[4] = sx[4].wrapping_add(ex[4]);
        sx[5] = sx[5].wrapping_add(ex[5]);
        sx[6] = sx[6].wrapping_add(ex[6]);
        sx[7] = sx[7].wrapping_add(ex[7]);
    }

    fn store(&self, out: &mut [u8]) {
        for (i, &e) in self.0.iter().enumerate() {
            store_be(out, i * 4, e);
        }
    }

    fn blocks(&mut self, mut input: &[u8]) -> usize {
        let mut t = *self;
        let mut inlen = input.len();
        while inlen >= 64 {
            let mut w = W::new(input);
            w.G(&mut t, 0);
            w.expand();
            w.G(&mut t, 1);
            w.expand();
            w.G(&mut t, 2);
            w.expand();
            w.G(&mut t, 3);
            t.add(self);
            self.0 = t.0;
            input = &input[64..];
            inlen -= 64;
        }
        inlen
    }
}

#[derive(Copy, Clone)]
/// SHA-256 hash implementation.
///
/// This struct provides both streaming and one-shot APIs for computing SHA-256 hashes.
///
/// # Examples
///
/// One-shot hashing:
/// ```
/// let hash = hmac_sha256::Hash::hash(b"hello world");
/// ```
///
/// Incremental hashing:
/// ```
/// let mut hasher = hmac_sha256::Hash::new();
/// hasher.update(b"hello ");
/// hasher.update(b"world");
/// let hash = hasher.finalize();
/// ```
pub struct Hash {
    state: State,
    w: [u8; 64],
    r: usize,
    len: usize,
}

impl Hash {
    /// Creates a new SHA-256 hasher.
    pub fn new() -> Hash {
        Hash {
            state: State::new(),
            r: 0,
            w: [0u8; 64],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn new_with_state(bytes: [u8; 32], original_input_length: usize) -> Hash {
        let mut be_bytes = [0u32; 8];
        for i in 0..8 {
            be_bytes[i] = u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        }
        Hash {
            state: State(be_bytes),
            r: 0,
            w: [0u8; 64],
            len: original_input_length,
        }
    }

    fn _update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        let mut n = input.len();
        self.len += n;
        let av = 64 - self.r;
        let tc = ::core::cmp::min(n, av);
        self.w[self.r..self.r + tc].copy_from_slice(&input[0..tc]);
        self.r += tc;
        n -= tc;
        let pos = tc;
        if self.r == 64 {
            self.state.blocks(&self.w);
            self.r = 0;
        }
        if self.r == 0 && n > 0 {
            let rb = self.state.blocks(&input[pos..]);
            if rb > 0 {
                self.w[..rb].copy_from_slice(&input[pos + n - rb..]);
                self.r = rb;
            }
        }
    }

    /// Absorbs content into the hasher state.
    ///
    /// This method can be called multiple times to incrementally add data to be hashed.
    ///
    /// # Example
    ///
    /// ```
    /// let mut hasher = hmac_sha256::Hash::new();
    /// hasher.update(b"first chunk");
    /// hasher.update(b"second chunk");
    /// let hash = hasher.finalize();
    /// ```
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self._update(input)
    }

    /// Computes the SHA-256 hash of all previously absorbed content.
    ///
    /// This method consumes the hasher and returns the computed 32-byte digest.
    ///
    /// # Example
    ///
    /// ```
    /// let mut hasher = hmac_sha256::Hash::new();
    /// hasher.update(b"data to hash");
    /// let hash: [u8; 32] = hasher.finalize();
    /// ```
    pub fn finalize(mut self) -> [u8; 32] {
        let mut padded = [0u8; 128];
        padded[..self.r].copy_from_slice(&self.w[..self.r]);
        padded[self.r] = 0x80;
        let r = if self.r < 56 { 64 } else { 128 };
        let bits = self.len * 8;
        for i in 0..8 {
            padded[r - 8 + i] = (bits as u64 >> (56 - i * 8)) as u8;
        }
        self.state.blocks(&padded[..r]);
        let mut out = [0u8; 32];
        self.state.store(&mut out);
        out
    }

    /// Verifies that the hash of absorbed content matches the expected digest.
    ///
    /// This provides constant-time comparison to prevent timing attacks.
    ///
    /// # Example
    ///
    /// ```
    /// let expected = hmac_sha256::Hash::hash(b"original data");
    ///
    /// let mut hasher = hmac_sha256::Hash::new();
    /// hasher.update(b"original data");
    /// assert!(hasher.finalize_verify(&expected));
    ///
    /// let mut hasher = hmac_sha256::Hash::new();
    /// hasher.update(b"modified data");
    /// assert!(!hasher.finalize_verify(&expected));
    /// ```
    pub fn finalize_verify(self, expected: &[u8; 32]) -> bool {
        let out = self.finalize();
        verify(&out, expected)
    }

    /// Hashes the provided input and verifies it against the expected digest in a single operation.
    ///
    /// This is a convenience method that combines hashing and verification in a single call.
    /// It provides constant-time comparison to prevent timing attacks.
    ///
    /// # Example
    ///
    /// ```
    /// let expected = hmac_sha256::Hash::hash(b"original data");
    ///
    /// // Verify in one shot
    /// assert!(hmac_sha256::Hash::verify(b"original data", &expected));
    /// assert!(!hmac_sha256::Hash::verify(b"modified data", &expected));
    /// ```
    pub fn verify(input: impl AsRef<[u8]>, expected: &[u8; 32]) -> bool {
        let hash = Self::hash(input.as_ref());
        verify(&hash, expected)
    }

    /// Verifies that the hash of absorbed content matches the expected digest using a reference.
    ///
    /// This method accepts a reference to a slice of bytes and verifies against it using
    /// constant-time comparison to prevent timing attacks. Unlike `finalize_verify`, this method
    /// does not require the expected value to be exactly 32 bytes, but will return `false` if
    /// the length is not 32 bytes.
    ///
    /// # Arguments
    ///
    /// * `expected` - The expected hash value to compare against
    ///
    /// # Returns
    ///
    /// `true` if the computed hash matches the expected value, `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// let expected = hmac_sha256::Hash::hash(b"original data");
    ///
    /// let mut hasher = hmac_sha256::Hash::new();
    /// hasher.update(b"original data");
    /// assert!(hasher.verify_with_ref(&expected));
    ///
    /// // Can also verify with a slice
    /// let expected_slice = &expected[..];
    /// let mut hasher2 = hmac_sha256::Hash::new();
    /// hasher2.update(b"original data");
    /// assert!(hasher2.verify_with_ref(expected_slice));
    ///
    /// // Or use the one-shot verification
    /// assert!(hmac_sha256::Hash::verify(b"original data", &expected));
    /// ```
    pub fn verify_with_ref(self, expected: &[u8]) -> bool {
        if expected.len() != 32 {
            return false;
        }
        let out = self.finalize();
        verify(&out, expected)
    }

    /// Computes the SHA-256 hash of the provided input in a single operation.
    ///
    /// This is a convenience method for simple hashing operations.
    ///
    /// # Example
    ///
    /// ```
    /// let hash = hmac_sha256::Hash::hash(b"data to hash");
    /// ```
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut h = Hash::new();
        h.update(input);
        h.finalize()
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::new()
    }
}
