//! Envelope v1 (spec-g2-g5.md section 3): plaintext, encryption, wire layout, binding.
//!
//! Pure functions, no network, no iroha dependency. The node (patch P2) parses the wire layout and
//! recomputes the binding but never decrypts; `rd2` decrypts (BI audit, recipient scan).

use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core_06::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: &[u8; 4] = b"RDE1";
const HKDF_INFO: &[u8] = b"rd.iroha2.envelope.v1";
const BINDING_TAG: &[u8] = b"rd.iroha2.binding.v1";
/// Minimum ciphertext length (Poly1305 tag 16 bytes + at least 1 byte of plaintext).
pub const MIN_CT: usize = 17;

pub type Bytes32 = [u8; 32];

// ---------------------------------------------------------------------------------------------
// Plaintext (3.1)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRef {
    pub nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputNote {
    pub amount: String,
    pub rho: String,
    pub diversifier: String,
    pub owner_tag: String,
    pub owner: String,
}

/// Field order is the wire order of the JSON (serde_json keeps struct order, no whitespace).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plaintext {
    pub v: u8,
    pub kind: String,
    pub asset: String,
    pub sender: String,
    pub reference: String,
    pub inputs: Vec<InputRef>,
    pub outputs: Vec<OutputNote>,
    pub public_amount: Option<String>,
}

impl Plaintext {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("plaintext serializes")
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvError {
    Truncated,
    BadMagic,
    TrailingBytes,
    BadAsset,
    ShortCiphertext,
    TooMany,
    /// AEAD failed (wrong key or tampered ciphertext or wrong aad).
    Decrypt,
    /// Plaintext is not valid envelope JSON of version 1.
    BadPlaintext(String),
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "envelope truncated"),
            Self::BadMagic => write!(f, "envelope magic is not RDE1"),
            Self::TrailingBytes => write!(f, "envelope has trailing bytes"),
            Self::BadAsset => write!(f, "envelope asset is not utf-8"),
            Self::ShortCiphertext => write!(f, "ciphertext shorter than {MIN_CT} bytes"),
            Self::TooMany => write!(f, "more than 255 inputs or outputs"),
            Self::Decrypt => write!(f, "decryption failed"),
            Self::BadPlaintext(m) => write!(f, "bad plaintext: {m}"),
        }
    }
}

impl std::error::Error for EnvError {}

// ---------------------------------------------------------------------------------------------
// Binding (3.4)
// ---------------------------------------------------------------------------------------------

/// Instruction fields the binding covers. Shield: `inputs` empty, `outputs = [note_commitment]`,
/// `public_amount = amount`. ZkTransfer: `public_amount = 0`. Unshield: change outputs (may be empty).
#[derive(Clone, Copy, Debug)]
pub struct BindingCtx<'a> {
    pub asset: &'a str,
    pub inputs: &'a [Bytes32],
    pub outputs: &'a [Bytes32],
    pub public_amount: u128,
}

fn sha256(data: &[u8]) -> Bytes32 {
    Sha256::digest(data).into()
}

pub fn compute_binding(
    ctx: &BindingCtx<'_>,
    key_version: u32,
    ct_bi: &[u8],
    ct_rc: &[u8],
) -> Result<Bytes32, EnvError> {
    let asset_len = u16::try_from(ctx.asset.len()).map_err(|_| EnvError::TooMany)?;
    let n_in = u8::try_from(ctx.inputs.len()).map_err(|_| EnvError::TooMany)?;
    let n_out = u8::try_from(ctx.outputs.len()).map_err(|_| EnvError::TooMany)?;
    let mut h = Sha256::new();
    h.update(BINDING_TAG);
    h.update(asset_len.to_be_bytes());
    h.update(ctx.asset.as_bytes());
    h.update([n_in]);
    for n in ctx.inputs {
        h.update(n);
    }
    h.update([n_out]);
    for o in ctx.outputs {
        h.update(o);
    }
    h.update(ctx.public_amount.to_be_bytes());
    h.update(key_version.to_be_bytes());
    h.update(sha256(ct_bi));
    h.update(sha256(ct_rc));
    Ok(h.finalize().into())
}

// ---------------------------------------------------------------------------------------------
// Encryption (3.2)
// ---------------------------------------------------------------------------------------------

fn aad(key_version: u32, asset: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(8 + asset.len());
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(&key_version.to_be_bytes());
    a.extend_from_slice(asset.as_bytes());
    a
}

fn derive_key(shared: &[u8; 32], eph_pk: &Bytes32, recv_pk: &Bytes32) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pk);
    salt[32..].copy_from_slice(recv_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut k = [0u8; 32];
    hk.expand(HKDF_INFO, &mut k).expect("32 bytes is a valid hkdf length");
    k
}

/// X25519 public key for a secret (32 bytes).
pub fn public_from_secret(secret: &Bytes32) -> Bytes32 {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Encrypt `plaintext` for `receiver_pk` with a given ephemeral secret and nonce.
/// Returns `(E, ct)`.
pub fn encrypt_for(
    plaintext: &[u8],
    asset: &str,
    key_version: u32,
    receiver_pk: &Bytes32,
    eph_secret: &Bytes32,
    nonce: &[u8; 24],
) -> (Bytes32, Vec<u8>) {
    let e = StaticSecret::from(*eph_secret);
    let e_pk = PublicKey::from(&e).to_bytes();
    let shared = e.diffie_hellman(&PublicKey::from(*receiver_pk));
    let k = derive_key(shared.as_bytes(), &e_pk, receiver_pk);
    let cipher = XChaCha20Poly1305::new((&k).into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad(key_version, asset),
            },
        )
        .expect("xchacha20poly1305 encrypt cannot fail for in-memory data");
    (e_pk, ct)
}

fn decrypt_with(
    secret: &Bytes32,
    e_pk: &Bytes32,
    nonce: &[u8; 24],
    ct: &[u8],
    asset: &str,
    key_version: u32,
) -> Result<Vec<u8>, EnvError> {
    let me = StaticSecret::from(*secret);
    let my_pk = PublicKey::from(&me).to_bytes();
    let shared = me.diffie_hellman(&PublicKey::from(*e_pk));
    let k = derive_key(shared.as_bytes(), e_pk, &my_pk);
    let cipher = XChaCha20Poly1305::new((&k).into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad(key_version, asset),
            },
        )
        .map_err(|_| EnvError::Decrypt)
}

// ---------------------------------------------------------------------------------------------
// Wire layout (3.3)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub key_version: u32,
    pub asset: String,
    pub e_bi: Bytes32,
    pub nonce_bi: [u8; 24],
    pub ct_bi: Vec<u8>,
    pub e_rc: Bytes32,
    pub nonce_rc: [u8; 24],
    pub ct_rc: Vec<u8>,
    pub binding: Bytes32,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EnvError> {
        if self.0.len() < n {
            return Err(EnvError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], EnvError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u16(&mut self) -> Result<u16, EnvError> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, EnvError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
}

impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(MAGIC);
        o.extend_from_slice(&self.key_version.to_be_bytes());
        o.extend_from_slice(&(self.asset.len() as u16).to_be_bytes());
        o.extend_from_slice(self.asset.as_bytes());
        o.extend_from_slice(&self.e_bi);
        o.extend_from_slice(&self.nonce_bi);
        o.extend_from_slice(&(self.ct_bi.len() as u32).to_be_bytes());
        o.extend_from_slice(&self.ct_bi);
        o.extend_from_slice(&self.e_rc);
        o.extend_from_slice(&self.nonce_rc);
        o.extend_from_slice(&(self.ct_rc.len() as u32).to_be_bytes());
        o.extend_from_slice(&self.ct_rc);
        o.extend_from_slice(&self.binding);
        o
    }

    /// Exact parse: no trailing bytes, both ciphertexts at least `MIN_CT`.
    pub fn parse(bytes: &[u8]) -> Result<Self, EnvError> {
        let mut r = Reader(bytes);
        if &r.arr::<4>()? != MAGIC {
            return Err(EnvError::BadMagic);
        }
        let key_version = r.u32()?;
        let asset_len = r.u16()? as usize;
        let asset = std::str::from_utf8(r.take(asset_len)?)
            .map_err(|_| EnvError::BadAsset)?
            .to_owned();
        let e_bi = r.arr()?;
        let nonce_bi = r.arr()?;
        let ct_bi_len = r.u32()? as usize;
        let ct_bi = r.take(ct_bi_len)?.to_vec();
        let e_rc = r.arr()?;
        let nonce_rc = r.arr()?;
        let ct_rc_len = r.u32()? as usize;
        let ct_rc = r.take(ct_rc_len)?.to_vec();
        let binding = r.arr()?;
        if !r.0.is_empty() {
            return Err(EnvError::TrailingBytes);
        }
        if ct_bi.len() < MIN_CT || ct_rc.len() < MIN_CT {
            return Err(EnvError::ShortCiphertext);
        }
        Ok(Self {
            key_version,
            asset,
            e_bi,
            nonce_bi,
            ct_bi,
            e_rc,
            nonce_rc,
            ct_rc,
            binding,
        })
    }

    /// Binding the node recomputes for these instruction fields.
    pub fn expected_binding(&self, ctx: &BindingCtx<'_>) -> Result<Bytes32, EnvError> {
        compute_binding(ctx, self.key_version, &self.ct_bi, &self.ct_rc)
    }

    /// True if `binding` matches the instruction fields and `asset` equals `ctx.asset`.
    pub fn binds(&self, ctx: &BindingCtx<'_>) -> bool {
        self.asset == ctx.asset && self.expected_binding(ctx).is_ok_and(|b| b == self.binding)
    }

    fn open(&self, secret: &Bytes32, bi_side: bool) -> Result<Plaintext, EnvError> {
        let (e, n, ct) = if bi_side {
            (&self.e_bi, &self.nonce_bi, &self.ct_bi)
        } else {
            (&self.e_rc, &self.nonce_rc, &self.ct_rc)
        };
        let pt = decrypt_with(secret, e, n, ct, &self.asset, self.key_version)?;
        let p: Plaintext =
            serde_json::from_slice(&pt).map_err(|e| EnvError::BadPlaintext(e.to_string()))?;
        if p.v != 1 {
            return Err(EnvError::BadPlaintext(format!("unsupported version {}", p.v)));
        }
        Ok(p)
    }

    /// Decrypt the BI audit ciphertext.
    pub fn open_bi(&self, audit_secret: &Bytes32) -> Result<Plaintext, EnvError> {
        self.open(audit_secret, true)
    }

    /// Decrypt the recipient ciphertext.
    pub fn open_rc(&self, view_secret: &Bytes32) -> Result<Plaintext, EnvError> {
        self.open(view_secret, false)
    }

    /// Re-compute the binding after a field was changed (attack tooling and tests).
    pub fn with_binding(mut self, ctx: &BindingCtx<'_>) -> Result<Self, EnvError> {
        self.binding = self.expected_binding(ctx)?;
        Ok(self)
    }
}

// ---------------------------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------------------------

/// All randomness of `seal`, explicit so that test vectors are deterministic.
#[derive(Clone, Debug)]
pub struct SealParams {
    pub key_version: u32,
    pub bi_pk: Bytes32,
    pub rc_pk: Bytes32,
    pub eph_bi: Bytes32,
    pub eph_rc: Bytes32,
    pub nonce_bi: [u8; 24],
    pub nonce_rc: [u8; 24],
}

impl SealParams {
    pub fn random(key_version: u32, bi_pk: Bytes32, rc_pk: Bytes32) -> Self {
        let mut p = Self {
            key_version,
            bi_pk,
            rc_pk,
            eph_bi: [0; 32],
            eph_rc: [0; 32],
            nonce_bi: [0; 24],
            nonce_rc: [0; 24],
        };
        OsRng.fill_bytes(&mut p.eph_bi);
        OsRng.fill_bytes(&mut p.eph_rc);
        OsRng.fill_bytes(&mut p.nonce_bi);
        OsRng.fill_bytes(&mut p.nonce_rc);
        p
    }
}

/// Encrypt the plaintext for BI and for the recipient and compute the binding.
pub fn seal(
    plaintext: &Plaintext,
    ctx: &BindingCtx<'_>,
    p: &SealParams,
) -> Result<Envelope, EnvError> {
    let pt = plaintext.to_bytes();
    let (e_bi, ct_bi) = encrypt_for(&pt, ctx.asset, p.key_version, &p.bi_pk, &p.eph_bi, &p.nonce_bi);
    let (e_rc, ct_rc) = encrypt_for(&pt, ctx.asset, p.key_version, &p.rc_pk, &p.eph_rc, &p.nonce_rc);
    let binding = compute_binding(ctx, p.key_version, &ct_bi, &ct_rc)?;
    Ok(Envelope {
        key_version: p.key_version,
        asset: ctx.asset.to_owned(),
        e_bi,
        nonce_bi: p.nonce_bi,
        ct_bi,
        e_rc,
        nonce_rc: p.nonce_rc,
        ct_rc,
        binding,
    })
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(tag: &str) -> Bytes32 {
        sha256(tag.as_bytes())
    }

    fn sample() -> (Plaintext, Vec<Bytes32>, Vec<Bytes32>, Bytes32, Bytes32, SealParams) {
        let bi_sk = h32("bi.audit.sk");
        let rc_sk = h32("bank-b.view.sk");
        let nulls = vec![h32("null0")];
        let outs = vec![h32("out0"), h32("out1")];
        let pt = Plaintext {
            v: 1,
            kind: "transfer".into(),
            asset: "rd#rd".into(),
            sender: "bank-a".into(),
            reference: "ref-1".into(),
            inputs: vec![InputRef { nullifier: hex::encode(nulls[0]) }],
            outputs: vec![OutputNote {
                amount: "100".into(),
                rho: hex::encode(h32("rho0")),
                diversifier: hex::encode(h32("div0")),
                owner_tag: hex::encode(h32("tag0")),
                owner: "bank-b".into(),
            }],
            public_amount: None,
        };
        let params = SealParams {
            key_version: 1,
            bi_pk: public_from_secret(&bi_sk),
            rc_pk: public_from_secret(&rc_sk),
            eph_bi: h32("eph-bi"),
            eph_rc: h32("eph-rc"),
            nonce_bi: h32("nonce-bi")[..24].try_into().unwrap(),
            nonce_rc: h32("nonce-rc")[..24].try_into().unwrap(),
        };
        (pt, nulls, outs, bi_sk, rc_sk, params)
    }

    #[test]
    fn plaintext_json_is_ordered_and_compact() {
        let (pt, ..) = sample();
        let s = String::from_utf8(pt.to_bytes()).unwrap();
        assert!(s.starts_with(r#"{"v":1,"kind":"transfer","asset":"rd#rd","sender":"bank-a","reference":"ref-1","inputs":[{"nullifier":""#));
        assert!(s.ends_with(r#""owner":"bank-b"}],"public_amount":null}"#));
        assert!(!s.contains(' '));
    }

    #[test]
    fn round_trip_both_sides() {
        let (pt, nulls, outs, bi_sk, rc_sk, params) = sample();
        let ctx = BindingCtx { asset: "rd#rd", inputs: &nulls, outputs: &outs, public_amount: 0 };
        let env = seal(&pt, &ctx, &params).unwrap();
        let wire = env.encode();
        let parsed = Envelope::parse(&wire).unwrap();
        assert_eq!(parsed, env);
        assert!(parsed.binds(&ctx));
        assert_eq!(parsed.open_bi(&bi_sk).unwrap(), pt);
        assert_eq!(parsed.open_rc(&rc_sk).unwrap(), pt);
    }

    #[test]
    fn layout_lengths() {
        let (pt, nulls, outs, _, _, params) = sample();
        let ctx = BindingCtx { asset: "rd#rd", inputs: &nulls, outputs: &outs, public_amount: 0 };
        let env = seal(&pt, &ctx, &params).unwrap();
        let wire = env.encode();
        let n = pt.to_bytes().len() + 16;
        assert_eq!(env.ct_bi.len(), n);
        assert_eq!(wire.len(), 4 + 4 + 2 + 5 + (32 + 24 + 4 + n) * 2 + 32);
        assert_eq!(&wire[..4], b"RDE1");
        assert_eq!(&wire[4..8], &1u32.to_be_bytes());
        assert_eq!(&wire[8..10], &5u16.to_be_bytes());
        assert_eq!(&wire[10..15], b"rd#rd");
        assert_eq!(&wire[wire.len() - 32..], &env.binding);
    }

    #[test]
    fn binding_mismatch_detected() {
        let (pt, nulls, outs, _, _, params) = sample();
        let ctx = BindingCtx { asset: "rd#rd", inputs: &nulls, outputs: &outs, public_amount: 0 };
        let env = seal(&pt, &ctx, &params).unwrap();
        let other_outs = vec![h32("out0"), h32("outX")];
        let c2 = BindingCtx { outputs: &other_outs, ..ctx };
        assert!(!env.binds(&c2));
        let c3 = BindingCtx { public_amount: 1, ..ctx };
        assert!(!env.binds(&c3));
        let c4 = BindingCtx { asset: "rd#other", ..ctx };
        assert!(!env.binds(&c4));
        let c5 = BindingCtx { inputs: &[], ..ctx };
        assert!(!env.binds(&c5));
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let (pt, nulls, outs, bi_sk, rc_sk, params) = sample();
        let ctx = BindingCtx { asset: "rd#rd", inputs: &nulls, outputs: &outs, public_amount: 0 };
        let env = seal(&pt, &ctx, &params).unwrap();
        assert_eq!(env.open_bi(&rc_sk), Err(EnvError::Decrypt));
        assert_eq!(env.open_rc(&bi_sk), Err(EnvError::Decrypt));
        let mut t = env.clone();
        t.ct_bi[3] ^= 1;
        assert_eq!(t.open_bi(&bi_sk), Err(EnvError::Decrypt));
        // key version is in the aad
        let mut t = env.clone();
        t.key_version = 2;
        assert_eq!(t.open_bi(&bi_sk), Err(EnvError::Decrypt));
    }

    #[test]
    fn parse_rejects_malformed() {
        let (pt, nulls, outs, _, _, params) = sample();
        let ctx = BindingCtx { asset: "rd#rd", inputs: &nulls, outputs: &outs, public_amount: 0 };
        let wire = seal(&pt, &ctx, &params).unwrap().encode();
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(Envelope::parse(&trailing), Err(EnvError::TrailingBytes));
        assert_eq!(Envelope::parse(&wire[..wire.len() - 1]), Err(EnvError::Truncated));
        let mut magic = wire.clone();
        magic[0] = b'X';
        assert_eq!(Envelope::parse(&magic), Err(EnvError::BadMagic));
        let mut env = Envelope::parse(&wire).unwrap();
        env.ct_rc.truncate(16);
        assert_eq!(Envelope::parse(&env.encode()), Err(EnvError::ShortCiphertext));
    }
}
