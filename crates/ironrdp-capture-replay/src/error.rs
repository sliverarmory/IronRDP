use std::io;

use thiserror::Error;

/// Errors that make an offline replay unreliable.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// The capture could not be read.
    #[error("failed to read capture")]
    Io(#[source] io::Error),
    /// The capture could not be parsed.
    #[error("invalid pcapng capture: {0}")]
    Pcap(String),
    /// The capture does not contain a supported direct TCP flow.
    #[error("capture does not contain an Ethernet direct TCP flow")]
    UnsupportedTransport,
    /// The capture has incomplete or contradictory TCP data.
    #[error("capture does not contain a complete client/server TCP flow")]
    MissingTcpFlow,
    /// The capture uses Standard RDP Security instead of TLS.
    #[error("capture uses Standard RDP Security without decryptable session keys")]
    StandardSecurity,
    /// The TLS protocol version or cipher suite is unsupported.
    #[error("capture TLS version or cipher suite is unsupported")]
    UnsupportedTls,
    /// The capture lacks the key-log entry required to decrypt its TLS session.
    #[error("capture does not include an NSS TLS secret for the negotiated session")]
    MissingTlsSecret,
    /// The capture lacks the key-log entry for the gateway-tunneled TLS session.
    #[error(
        "capture does not include an NSS TLS secret for the gateway-tunneled session; supply the original key log with --keylog or Capture::add_tls_key_log"
    )]
    MissingTunneledTlsSecret,
    /// TLS record authentication failed.
    #[error("capture TLS authentication failed")]
    TlsAuthentication,
    /// The capture requires unsupported TLS 1.3 key rotation.
    #[error("capture uses unsupported TLS 1.3 key rotation")]
    TlsKeyUpdate,
    /// The capture does not contain a complete RDP connection sequence.
    #[error("capture does not contain enough negotiated RDP state")]
    MissingRdpState,
    /// The decrypted stream begins with CredSSP (NLA) messages that RDP framing cannot skip.
    #[error("capture begins with CredSSP messages that replay cannot frame")]
    CredsspPrefix,
    /// The server did not assign all requested static channels.
    #[error("capture does not contain server-assigned static channel IDs")]
    MissingChannelMap,
    /// The MCS user channel could not be recovered.
    #[error("capture does not contain the client MCS user channel")]
    MissingUserChannel,
    /// The active RDP share identifier could not be recovered.
    #[error("capture does not contain an activated RDP share ID")]
    MissingShareId,
    /// Captured connection state cannot configure an offline router safely.
    #[error("capture contains contradictory routing state")]
    ContradictoryRoutingState,
    /// The capture requires the DRDYNVC static channel.
    #[error("capture does not contain the DRDYNVC static channel")]
    MissingDrdynvcChannel,
    /// A captured dynamic channel could not be attached.
    #[error("captured dynamic channel could not be attached")]
    DynamicChannelAttachment,
    /// The gateway tunnel framing is incomplete or malformed.
    #[error("capture gateway tunnel framing is invalid: {0}")]
    GatewayFraming(String),
}

impl ReplayError {
    /// Stable reason code when this error is a documented replay limitation.
    ///
    /// Returns `None` for unreadable input and failures that indicate a replay defect.
    pub fn unsupported_reason(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedTransport => Some("unsupported-transport"),
            Self::StandardSecurity => Some("standard-security"),
            Self::UnsupportedTls => Some("unsupported-tls"),
            Self::MissingTunneledTlsSecret => Some("missing-tunneled-tls-secret"),
            Self::TlsKeyUpdate => Some("tls-key-update"),
            Self::MissingRdpState => Some("missing-rdp-state"),
            Self::CredsspPrefix => Some("credssp-prefix"),
            Self::MissingDrdynvcChannel => Some("missing-drdynvc-channel"),
            Self::DynamicChannelAttachment => Some("dynamic-channel-attachment"),
            Self::Io(_)
            | Self::Pcap(_)
            | Self::MissingTcpFlow
            | Self::MissingTlsSecret
            | Self::TlsAuthentication
            | Self::MissingChannelMap
            | Self::MissingUserChannel
            | Self::MissingShareId
            | Self::ContradictoryRoutingState
            | Self::GatewayFraming(_) => None,
        }
    }
}
