use core::convert::TryFrom;

use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::errors::Error;
use pasetors::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
use pasetors::token::{Binding, ImplicitAssertion, Local, Public, UntrustedToken};
use pasetors::{local, public, version4::V4};

#[test]
fn empty_binding_is_rejected_instead_of_silently_degrading() {
    assert_eq!(
        ImplicitAssertion::bound(b"").unwrap_err(),
        Error::EmptyImplicitAssertion
    );

    let context = ImplicitAssertion::bound(b"session-abc").unwrap();
    assert_eq!(context, ImplicitAssertion::Bound(b"session-abc".to_vec()));

    // Constructing the variant directly must not bypass the empty-material rejection.
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let claims = Claims::new().unwrap();
    assert_eq!(
        public::sign(
            &kp.secret,
            &claims,
            None,
            &ImplicitAssertion::Bound(Vec::new())
        )
        .unwrap_err(),
        Error::EmptyImplicitAssertion
    );
}

#[test]
fn public_tokens_are_bound_to_their_session_context() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let claims = Claims::new().unwrap();
    let rules = ClaimsValidationRules::new();

    let session_a = ImplicitAssertion::bound(b"session-a").unwrap();
    let session_b = ImplicitAssertion::bound(b"session-b").unwrap();

    let token = public::sign(&kp.secret, &claims, None, &session_a).unwrap();
    let untrusted = UntrustedToken::<Public, V4>::try_from(&token).unwrap();

    // The matching context verifies and the binding source is reported.
    let trusted = public::verify(&kp.public, &untrusted, &rules, None, &session_a).unwrap();
    assert_eq!(
        trusted.implicit_assert_binding(),
        &Binding::Context(b"session-a".to_vec())
    );
    assert_eq!(trusted.implicit_assert(), b"session-a");

    // Session material cannot be interchanged across contexts.
    assert!(public::verify(&kp.public, &untrusted, &rules, None, &session_b).is_err());
    // A bound token is not silently accepted as unbound.
    assert!(
        public::verify(
            &kp.public,
            &untrusted,
            &rules,
            None,
            &ImplicitAssertion::Unbound
        )
        .is_err()
    );
}

#[test]
fn local_tokens_are_bound_to_their_session_context() {
    let sk = SymmetricKey::<V4>::generate().unwrap();
    let claims = Claims::new().unwrap();
    let rules = ClaimsValidationRules::new();

    let session_a = ImplicitAssertion::bound(b"session-a").unwrap();
    let session_b = ImplicitAssertion::bound(b"session-b").unwrap();

    let token = local::encrypt(&sk, &claims, None, &session_a).unwrap();
    let untrusted = UntrustedToken::<Local, V4>::try_from(&token).unwrap();

    let trusted = local::decrypt(&sk, &untrusted, &rules, None, &session_a).unwrap();
    assert_eq!(
        trusted.implicit_assert_binding(),
        &Binding::Context(b"session-a".to_vec())
    );

    assert!(local::decrypt(&sk, &untrusted, &rules, None, &session_b).is_err());
    assert!(local::decrypt(&sk, &untrusted, &rules, None, &ImplicitAssertion::Unbound).is_err());
}

#[test]
fn legacy_unbound_token_requires_explicit_unbound_choice() {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    let claims = Claims::new().unwrap();
    let rules = ClaimsValidationRules::new();

    // A token created without a binding (as allowed by older versions).
    let token = public::sign(&kp.secret, &claims, None, &ImplicitAssertion::Unbound).unwrap();
    let untrusted = UntrustedToken::<Public, V4>::try_from(&token).unwrap();

    let trusted = public::verify(
        &kp.public,
        &untrusted,
        &rules,
        None,
        &ImplicitAssertion::Unbound,
    )
    .unwrap();
    assert_eq!(trusted.implicit_assert_binding(), &Binding::None);
    assert!(trusted.implicit_assert().is_empty());

    // It must not verify against any context binding.
    let session = ImplicitAssertion::bound(b"session-a").unwrap();
    assert!(public::verify(&kp.public, &untrusted, &rules, None, &session).is_err());
}
