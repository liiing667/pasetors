#![cfg(all(feature = "std", feature = "paserk"))]
//! A PASERK ID (`kid`) in a token footer must form a single authorization
//! identity together with the token version, the `local`/`public` purpose and
//! the actual key. Combinations where these conflict must fail closed, even
//! when the same raw key bytes are valid across versions (e.g. Ed25519 keys
//! shared between `v2` and `v4`).

use core::convert::TryFrom;
use pasetors::footer::Footer;
use pasetors::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
use pasetors::paserk::Id;
use pasetors::token::UntrustedToken;
use pasetors::version4::{LocalToken as LocalToken4, PublicToken as PublicToken4, V4};
use pasetors::{Local, Public};

#[cfg(feature = "v2")]
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
#[cfg(feature = "v2")]
use pasetors::version2::{LocalToken as LocalToken2, PublicToken as PublicToken2, V2};
#[cfg(feature = "v3")]
use pasetors::version3::{PublicToken as PublicToken3, V3};

const MESSAGE: &[u8] = b"{\"data\":\"this is a signed message\"}";

fn footer_with_kid(id: &Id) -> Vec<u8> {
    let mut footer = Footer::new();
    footer.key_id(id);
    footer.to_string().unwrap().into_bytes()
}

#[test]
fn v4_legit_flows_with_matching_kid() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let footer = footer_with_kid(&Id::from(&kp.public));
    let token = PublicToken4::sign(&kp.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&kp.public, &ut, Some(&footer), None).is_ok());
    assert!(PublicToken4::verify(&kp.public, &ut, None, None).is_ok());

    let sk = SymmetricKey::<V4>::generate().unwrap();
    let footer = footer_with_kid(&Id::from(&sk));
    let token = LocalToken4::encrypt(&sk, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(LocalToken4::decrypt(&sk, &ut, Some(&footer), None).is_ok());
    assert!(LocalToken4::decrypt(&sk, &ut, None, None).is_ok());
}

#[cfg(feature = "v2")]
#[test]
fn v2_legit_flows_with_matching_kid() {
    let kp = AsymmetricKeyPair::<V2>::generate().unwrap();
    let footer = footer_with_kid(&Id::from(&kp.public));
    let token = PublicToken2::sign(&kp.secret, MESSAGE, Some(&footer)).unwrap();
    let ut = UntrustedToken::<Public, V2>::try_from(&token).unwrap();
    assert!(PublicToken2::verify(&kp.public, &ut, Some(&footer)).is_ok());

    let sk = SymmetricKey::<V2>::generate().unwrap();
    let footer = footer_with_kid(&Id::from(&sk));
    let token = LocalToken2::encrypt(&sk, MESSAGE, Some(&footer)).unwrap();
    let ut = UntrustedToken::<Local, V2>::try_from(&token).unwrap();
    assert!(LocalToken2::decrypt(&sk, &ut, Some(&footer)).is_ok());
}

#[cfg(feature = "v3")]
#[test]
fn v3_legit_flow_with_matching_kid() {
    let kp = AsymmetricKeyPair::<V3>::generate().unwrap();
    let footer = footer_with_kid(&Id::from(&kp.public));
    let token = PublicToken3::sign(&kp.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V3>::try_from(&token).unwrap();
    assert!(PublicToken3::verify(&kp.public, &ut, Some(&footer), None).is_ok());
}

#[test]
fn cross_purpose_kid_rejected() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let sk = SymmetricKey::<V4>::generate().unwrap();

    // A `local` key identity (lid) named in the footer of a `public` token.
    let footer = footer_with_kid(&Id::from(&sk));
    let token = PublicToken4::sign(&kp.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&kp.public, &ut, Some(&footer), None).is_err());

    // A `public` key identity (pid) named in the footer of a `local` token.
    let footer = footer_with_kid(&Id::from(&kp.public));
    let token = LocalToken4::encrypt(&sk, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(LocalToken4::decrypt(&sk, &ut, Some(&footer), None).is_err());

    // A secret key identity (sid) does not match the public key used to verify.
    let footer = footer_with_kid(&Id::from(&kp.secret));
    let token = PublicToken4::sign(&kp.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&kp.public, &ut, Some(&footer), None).is_err());
}

#[test]
fn kid_of_different_key_rejected() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let other = AsymmetricKeyPair::<V4>::generate().unwrap();

    let footer = footer_with_kid(&Id::from(&other.public));
    let token = PublicToken4::sign(&kp.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&kp.public, &ut, Some(&footer), None).is_err());

    let sk = SymmetricKey::<V4>::generate().unwrap();
    let other_sk = SymmetricKey::<V4>::generate().unwrap();
    let footer = footer_with_kid(&Id::from(&other_sk));
    let token = LocalToken4::encrypt(&sk, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(LocalToken4::decrypt(&sk, &ut, Some(&footer), None).is_err());
}

#[cfg(feature = "v2")]
#[test]
fn cross_version_same_key_bytes_rejected() {
    // Ed25519 keys are byte-compatible between v2 and v4: the very same key
    // can legitimately exist in both versions, so only the PASERK ID in the
    // footer distinguishes the authorized identity.
    let kp2 = AsymmetricKeyPair::<V2>::generate().unwrap();
    let pk4 = AsymmetricPublicKey::<V4>::from(kp2.public.as_bytes()).unwrap();
    let sk4 = AsymmetricSecretKey::<V4>::from(kp2.secret.as_bytes()).unwrap();

    // A v2 token whose footer names the v4 identity of the same key.
    let footer = footer_with_kid(&Id::from(&pk4));
    let token = PublicToken2::sign(&kp2.secret, MESSAGE, Some(&footer)).unwrap();
    let ut = UntrustedToken::<Public, V2>::try_from(&token).unwrap();
    assert!(PublicToken2::verify(&kp2.public, &ut, Some(&footer)).is_err());

    // A v4 token whose footer names the v2 identity of the same key.
    let footer = footer_with_kid(&Id::from(&kp2.public));
    let token = PublicToken4::sign(&sk4, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&pk4, &ut, Some(&footer), None).is_err());

    // The same symmetric key bytes are valid for both v2 and v4 `local`.
    let raw = [0x42u8; 32];
    let sk2 = SymmetricKey::<V2>::from(&raw).unwrap();
    let sk4 = SymmetricKey::<V4>::from(&raw).unwrap();

    let footer = footer_with_kid(&Id::from(&sk4));
    let token = LocalToken2::encrypt(&sk2, MESSAGE, Some(&footer)).unwrap();
    let ut = UntrustedToken::<Local, V2>::try_from(&token).unwrap();
    assert!(LocalToken2::decrypt(&sk2, &ut, Some(&footer)).is_err());

    let footer = footer_with_kid(&Id::from(&sk2));
    let token = LocalToken4::encrypt(&sk4, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(LocalToken4::decrypt(&sk4, &ut, Some(&footer), None).is_err());
}

#[cfg(feature = "v2")]
#[test]
fn old_public_kid_cannot_enter_local_trust_domain() {
    // A `k2.pid` identity (an old public-token key) written into the footer
    // of a v4 `local` token must not be accepted.
    let kp2 = AsymmetricKeyPair::<V2>::generate().unwrap();
    let sk4 = SymmetricKey::<V4>::generate().unwrap();

    let footer = footer_with_kid(&Id::from(&kp2.public));
    let token = LocalToken4::encrypt(&sk4, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(LocalToken4::decrypt(&sk4, &ut, Some(&footer), None).is_err());
}

#[cfg(feature = "v3")]
#[test]
fn cross_version_v3_v4_kid_rejected() {
    let kp3 = AsymmetricKeyPair::<V3>::generate().unwrap();
    let kp4 = AsymmetricKeyPair::<V4>::generate().unwrap();

    // A v3 token naming a v4 key identity.
    let footer = footer_with_kid(&Id::from(&kp4.public));
    let token = PublicToken3::sign(&kp3.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V3>::try_from(&token).unwrap();
    assert!(PublicToken3::verify(&kp3.public, &ut, Some(&footer), None).is_err());

    // A v4 token naming a v3 key identity.
    let footer = footer_with_kid(&Id::from(&kp3.public));
    let token = PublicToken4::sign(&kp4.secret, MESSAGE, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&kp4.public, &ut, Some(&footer), None).is_err());
}

#[test]
fn non_paserk_kid_unaffected() {
    // Footers whose `kid` is not a PASERK ID carry no PASERK key identity
    // and keep working as before (e.g. the official PASETO test vectors).
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    let token = PublicToken4::sign(&kp.secret, MESSAGE, Some(footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(PublicToken4::verify(&kp.public, &ut, Some(footer), None).is_ok());
}

#[test]
fn high_level_api_enforces_kid_binding() {
    use pasetors::claims::{Claims, ClaimsValidationRules};
    use pasetors::{local, public};

    let rules = ClaimsValidationRules::new();
    let claims = Claims::new().unwrap();

    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let mut footer = Footer::new();
    footer.key_id(&Id::from(&kp.public));
    let token = public::sign(&kp.secret, &claims, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(public::verify(&kp.public, &ut, &rules, Some(&footer), None).is_ok());

    // The footer names a `local` identity on a `public` token.
    let sk = SymmetricKey::<V4>::generate().unwrap();
    let mut confused_footer = Footer::new();
    confused_footer.key_id(&Id::from(&sk));
    let token = public::sign(&kp.secret, &claims, Some(&confused_footer), None).unwrap();
    let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
    assert!(public::verify(&kp.public, &ut, &rules, Some(&confused_footer), None).is_err());

    let mut footer = Footer::new();
    footer.key_id(&Id::from(&sk));
    let token = local::encrypt(&sk, &claims, Some(&footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(local::decrypt(&sk, &ut, &rules, Some(&footer), None).is_ok());

    // The footer names a `public` identity on a `local` token.
    let mut confused_footer = Footer::new();
    confused_footer.key_id(&Id::from(&kp.public));
    let token = local::encrypt(&sk, &claims, Some(&confused_footer), None).unwrap();
    let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
    assert!(local::decrypt(&sk, &ut, &rules, Some(&confused_footer), None).is_err());
}
