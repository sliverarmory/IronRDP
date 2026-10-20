use std::io;
use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::ServerName;

use crate::{CertificateValidation, CertificateValidationCallback, PeerCertificatePolicy, PeerCertificateStatus};

/// Builds the rustls client configuration used by an RDP transport.
///
/// A callback augments strict platform-root and server-name validation.
/// Combining a callback with the dangerous policy is rejected because the callback would never observe a validation failure.
///
/// # Panics
///
/// Panics if no process-level crypto provider is installed and rustls cannot unambiguously select one from the enabled provider features.
pub fn rustls_client_config(
    certificate_validation: CertificateValidation,
    endpoint: &str,
    callback: Option<CertificateValidationCallback>,
) -> io::Result<rustls::ClientConfig> {
    let verifier = server_cert_verifier(certificate_validation, endpoint, callback)?;
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

fn server_cert_verifier(
    certificate_validation: CertificateValidation,
    endpoint: &str,
    callback: Option<CertificateValidationCallback>,
) -> io::Result<Arc<dyn ServerCertVerifier>> {
    if callback.is_some() && certificate_validation != CertificateValidation::Strict {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a certificate-validation callback requires strict validation",
        ));
    }

    let verifier: Arc<dyn ServerCertVerifier> = match certificate_validation {
        CertificateValidation::Strict => {
            rustls::client::WebPkiServerVerifier::builder(Arc::new(platform_root_certificates()?))
                .build()
                .map_err(io::Error::other)?
        }
        CertificateValidation::DangerouslyAcceptInvalidCertificate => Arc::new(NoCertificateVerification),
    };

    Ok(match callback {
        Some(callback) => Arc::new(CallbackVerifier {
            verifier,
            endpoint: endpoint.to_owned(),
            callback: Some(callback),
            peer_policy: None,
        }),
        None => verifier,
    })
}

/// Builds a strict verifier with a typed authorization callback for every peer certificate.
pub fn rustls_client_config_with_peer_policy(
    endpoint: &str,
    policy: PeerCertificatePolicy,
) -> io::Result<rustls::ClientConfig> {
    let verifier = server_cert_verifier(CertificateValidation::Strict, endpoint, None)?;
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CallbackVerifier {
            verifier,
            endpoint: endpoint.to_owned(),
            callback: None,
            peer_policy: Some(policy),
        }))
        .with_no_client_auth();
    // No SSLKEYLOGFILE support for the embedding path; resumption must not bypass pin decisions.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

fn classify_certificate_error(error: &rustls::Error) -> PeerCertificateStatus {
    use rustls::CertificateError;
    match error {
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer) => PeerCertificateStatus::UnknownIssuer,
        rustls::Error::InvalidCertificate(CertificateError::Expired | CertificateError::ExpiredContext { .. }) => {
            PeerCertificateStatus::Expired
        }
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
        ) => PeerCertificateStatus::NotValidYet,
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => PeerCertificateStatus::NameMismatch,
        _ => PeerCertificateStatus::HardFailure,
    }
}

fn platform_root_certificates() -> io::Result<rustls::RootCertStore> {
    let native_certificates = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(native_certificates.certs);
    if added == 0 {
        return Err(io::Error::other(
            "the platform certificate store contains no usable roots",
        ));
    }

    Ok(roots)
}

struct CallbackVerifier {
    verifier: Arc<dyn ServerCertVerifier>,
    endpoint: String,
    callback: Option<CertificateValidationCallback>,
    peer_policy: Option<PeerCertificatePolicy>,
}

impl core::fmt::Debug for CallbackVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallbackVerifier")
    }
}

impl ServerCertVerifier for CallbackVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self
            .verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        if let Some(policy) = &self.peer_policy {
            let status = match &result {
                Ok(_) => PeerCertificateStatus::Valid,
                Err(error) => classify_certificate_error(error),
            };
            let approved = policy(end_entity.as_ref(), &self.endpoint, status);
            return match result {
                Ok(verified) if approved => Ok(verified),
                Err(_) if approved && status.can_override() => Ok(ServerCertVerified::assertion()),
                Err(error) => Err(error),
                Ok(_) => Err(rustls::Error::General(
                    "peer certificate policy rejected certificate".into(),
                )),
            };
        }
        match result {
            Ok(verified) => Ok(verified),
            Err(error)
                if self
                    .callback
                    .as_ref()
                    .is_some_and(|callback| callback(end_entity.as_ref(), &self.endpoint, &error.to_string())) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            Err(error) => Err(error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod peer_policy_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct TestVerifier {
        valid: bool,
    }
    impl ServerCertVerifier for TestVerifier {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if self.valid {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature,
                ))
            }
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("test signature".into()))
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("test signature".into()))
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            Vec::new()
        }
    }
    fn verify(verifier: &CallbackVerifier) -> Result<ServerCertVerified, rustls::Error> {
        verifier.verify_server_cert(
            &rustls::pki_types::CertificateDer::from(&b"test"[..]),
            &[],
            &ServerName::try_from("example.test").unwrap(),
            &[],
            rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
        )
    }
    #[test]
    fn policy_can_reject_a_pki_valid_replacement() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = calls.clone();
        let verifier = CallbackVerifier {
            verifier: Arc::new(TestVerifier { valid: true }),
            endpoint: "example.test:3389".into(),
            callback: None,
            peer_policy: Some(Arc::new(move |_, _, status| {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(status, PeerCertificateStatus::Valid);
                false
            })),
        };
        assert!(verify(&verifier).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn accepting_policy_cannot_override_a_bad_signature() {
        let verifier = CallbackVerifier {
            verifier: Arc::new(TestVerifier { valid: false }),
            endpoint: "example.test:3389".into(),
            callback: None,
            peer_policy: Some(Arc::new(|_, _, status| {
                assert_eq!(status, PeerCertificateStatus::HardFailure);
                true
            })),
        };
        assert!(verify(&verifier).is_err());
    }
    #[test]
    fn classification_is_structured_and_unknown_errors_fail_closed() {
        assert_eq!(
            classify_certificate_error(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            )),
            PeerCertificateStatus::UnknownIssuer
        );
        assert_eq!(
            classify_certificate_error(&rustls::Error::General("UnknownIssuer".into())),
            PeerCertificateStatus::HardFailure
        );
    }
}
