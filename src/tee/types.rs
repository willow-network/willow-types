//! Core types for Trusted Execution Environment (TEE) attestations.
//!
//! This module defines the data structures used to represent TEE attestations
//! from various hardware vendors (AWS Nitro, Intel SGX) and the verification
//! results.

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// TEE Type Enumeration
// ============================================================================

/// Supported Trusted Execution Environment types.
///
/// Each TEE type has different characteristics:
///
/// | Type      | Provider | Isolation Method    | Typical Use Case       |
/// |-----------|----------|---------------------|------------------------|
/// | AwsNitro  | AWS      | Virtualization      | Cloud indexers         |
/// | IntelSgx  | Intel    | CPU enclaves        | On-prem, multi-cloud   |
/// | AmdSev    | AMD      | Memory encryption   | AMD-based servers      |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeType {
    /// AWS Nitro Enclaves - virtualization-based isolation on EC2.
    ///
    /// Attestation uses CBOR-encoded COSE_Sign1 structure signed by
    /// AWS Nitro PKI. PCR values identify the enclave image.
    AwsNitro,

    /// Intel Software Guard Extensions (SGX) - CPU-based enclaves.
    ///
    /// Attestation uses SGX quotes signed by Intel's attestation service.
    /// MRENCLAVE value identifies the enclave code.
    IntelSgx,

    /// AMD Secure Encrypted Virtualization (SEV) - memory encryption.
    ///
    /// Currently a placeholder for future support.
    AmdSev,
}

impl TeeType {
    /// Returns the human-readable name of the TEE type.
    pub fn name(&self) -> &'static str {
        match self {
            TeeType::AwsNitro => "AWS Nitro Enclaves",
            TeeType::IntelSgx => "Intel SGX",
            TeeType::AmdSev => "AMD SEV",
        }
    }

    /// Returns the size in bytes of the enclave image hash for this TEE type.
    ///
    /// - Nitro PCR0: 48 bytes (SHA-384)
    /// - SGX MRENCLAVE: 32 bytes (SHA-256)
    /// - AMD SEV: 48 bytes (SHA-384)
    pub fn enclave_hash_size(&self) -> usize {
        match self {
            TeeType::AwsNitro => 48,
            TeeType::IntelSgx => 32,
            TeeType::AmdSev => 48,
        }
    }

    /// Returns whether this TEE type is currently fully supported.
    pub fn is_supported(&self) -> bool {
        match self {
            TeeType::AwsNitro => true,
            TeeType::IntelSgx => true,
            TeeType::AmdSev => false, // Future support
        }
    }
}

impl fmt::Display for TeeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// TEE Capability (Indexer Registration)
// ============================================================================

/// TEE capability declaration for indexer registration.
///
/// When an indexer registers with the network, they must prove they have
/// TEE capability by providing a valid attestation from their enclave.
/// This ensures only TEE-capable indexers can participate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeCapability {
    /// The type of TEE this indexer supports.
    pub tee_type: TeeType,

    /// Hash of the enclave image (PCR0 for Nitro, MRENCLAVE for SGX).
    ///
    /// This identifies the exact code running in the enclave.
    /// The hash size depends on the TEE type (48 bytes for Nitro, 32 for SGX).
    pub enclave_image_hash: Vec<u8>,

    /// Attestation proof demonstrating actual TEE capability.
    ///
    /// This is a serialized attestation document from the TEE hardware,
    /// proving the indexer actually has access to a TEE of the claimed type.
    pub attestation_proof: Vec<u8>,

    /// Timestamp when this capability was attested.
    pub attested_at: u64,
}

impl TeeCapability {
    /// Validates the basic structure of the TEE capability.
    pub fn validate(&self) -> Result<(), String> {
        // Check enclave hash size matches TEE type
        let expected_size = self.tee_type.enclave_hash_size();
        if self.enclave_image_hash.len() != expected_size {
            return Err(format!(
                "Enclave image hash size mismatch: expected {} bytes for {:?}, got {}",
                expected_size,
                self.tee_type,
                self.enclave_image_hash.len()
            ));
        }

        // Check attestation proof is present
        if self.attestation_proof.is_empty() {
            return Err("Attestation proof cannot be empty".to_string());
        }

        // Check TEE type is supported
        if !self.tee_type.is_supported() {
            return Err(format!("{:?} is not yet supported", self.tee_type));
        }

        Ok(())
    }
}

// ============================================================================
// TEE Attestation (Indexed Data Submission)
// ============================================================================

/// TEE attestation attached to an indexed data submission.
///
/// This attestation proves that the indexed data was processed inside
/// a trusted execution environment, and the enclave code was not tampered with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// The type of TEE that produced this attestation.
    pub tee_type: TeeType,

    /// AWS Nitro-specific attestation document.
    pub nitro_document: Option<NitroAttestationDocument>,

    /// Intel SGX-specific quote.
    pub sgx_quote: Option<SgxQuote>,

    /// SHA-256 hash of the indexed data being attested.
    ///
    /// This must match the hash of the submitted data batches.
    /// The enclave includes this in the attestation's user_data field.
    pub data_hash: [u8; 32],

    /// Timestamp when the attestation was generated (inside the enclave).
    pub timestamp: u64,

    /// Block range covered by this attestation.
    pub block_range: (u64, u64),
}

impl TeeAttestation {
    /// Returns the enclave image hash from the attestation.
    ///
    /// This is the PCR0 for Nitro or MRENCLAVE for SGX.
    pub fn enclave_image_hash(&self) -> Option<Vec<u8>> {
        match self.tee_type {
            TeeType::AwsNitro => self.nitro_document.as_ref().map(|doc| doc.pcr0.to_vec()),
            TeeType::IntelSgx => self.sgx_quote.as_ref().map(|q| q.mr_enclave.to_vec()),
            TeeType::AmdSev => None, // Not yet supported
        }
    }

    /// Validates the basic structure of the attestation.
    pub fn validate(&self) -> Result<(), String> {
        // Check that the appropriate document is present for the TEE type
        match self.tee_type {
            TeeType::AwsNitro => {
                if self.nitro_document.is_none() {
                    return Err("Nitro attestation document required for AwsNitro type".to_string());
                }
            }
            TeeType::IntelSgx => {
                if self.sgx_quote.is_none() {
                    return Err("SGX quote required for IntelSgx type".to_string());
                }
            }
            TeeType::AmdSev => {
                return Err("AMD SEV attestations are not yet supported".to_string());
            }
        }

        // Validate block range
        if self.block_range.0 > self.block_range.1 {
            return Err("Invalid block range: start must be <= end".to_string());
        }

        // Validate data hash is non-zero
        if self.data_hash == [0u8; 32] {
            return Err("Data hash cannot be zero".to_string());
        }

        Ok(())
    }
}

// ============================================================================
// AWS Nitro Attestation Document
// ============================================================================

/// AWS Nitro Enclave attestation document.
///
/// Nitro attestations are CBOR-encoded COSE_Sign1 structures signed by the
/// AWS Nitro Attestation PKI. The attestation contains PCR values that
/// uniquely identify the enclave image and its runtime configuration.
///
/// # PCR Values
///
/// - **PCR0**: Enclave image hash (identifies the code)
/// - **PCR1**: Linux kernel and bootstrap hash
/// - **PCR2**: Application hash
/// - **PCR3**: IAM role ARN (if assigned)
/// - **PCR4**: Instance ID
/// - **PCR8**: Enclave image signing certificate
///
/// # Verification
///
/// To verify a Nitro attestation:
/// 1. Parse the CBOR-encoded COSE_Sign1 structure
/// 2. Verify the certificate chain back to the AWS Nitro root CA
/// 3. Verify the COSE signature using the leaf certificate
/// 4. Extract and validate PCR values
/// 5. Check user_data matches expected data hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroAttestationDocument {
    /// Raw CBOR-encoded COSE_Sign1 attestation document.
    ///
    /// This is the complete attestation as returned by the Nitro hypervisor.
    pub raw_document: Vec<u8>,

    /// PCR0: Hash of the enclave image file (EIF).
    ///
    /// This is the primary identifier for the enclave code.
    /// Must be exactly 48 bytes (SHA-384).
    pub pcr0: Vec<u8>,

    /// PCR1: Hash of the Linux kernel and bootstrap.
    /// Must be exactly 48 bytes (SHA-384).
    pub pcr1: Vec<u8>,

    /// PCR2: Hash of the application.
    /// Must be exactly 48 bytes (SHA-384).
    pub pcr2: Vec<u8>,

    /// User-provided data included in the attestation.
    ///
    /// For Willow indexers, this contains the SHA-256 hash of the indexed data.
    /// Max 512 bytes.
    pub user_data: Vec<u8>,

    /// Public key from the attestation (if included).
    ///
    /// Can be used to establish a secure channel with the enclave.
    pub public_key: Option<Vec<u8>>,

    /// Nonce provided when requesting the attestation.
    ///
    /// Used to prevent replay attacks.
    pub nonce: Option<Vec<u8>>,

    /// DER-encoded certificate chain from the attestation.
    ///
    /// The chain should verify back to the AWS Nitro root CA.
    pub certificate_chain: Vec<Vec<u8>>,

    /// Timestamp from the attestation document (milliseconds since Unix epoch).
    ///
    /// Note: AWS Nitro uses milliseconds for timestamps. This is converted to
    /// seconds when creating `VerifiedTeeAttestation` for consistency.
    pub timestamp: u64,
}

impl NitroAttestationDocument {
    /// Creates a new Nitro attestation document from raw bytes.
    ///
    /// This performs basic parsing but does NOT verify the attestation.
    /// Use `NitroVerifier::verify_attestation` for full verification.
    ///
    /// The raw document is a COSE_Sign1 structure containing:
    /// - Protected header (algorithm info)
    /// - Unprotected header (empty)
    /// - Payload (CBOR-encoded attestation document)
    /// - Signature (ECDSA signature)
    pub fn from_raw(raw_document: Vec<u8>) -> Result<Self, TeeVerificationError> {
        use ciborium::Value;
        use std::io::Cursor;

        if raw_document.is_empty() {
            return Err(TeeVerificationError::ParseError(
                "Empty attestation document".to_string(),
            ));
        }

        // Parse the COSE_Sign1 structure (CBOR array with tag 18)
        let cursor = Cursor::new(&raw_document);
        let cose: Value = ciborium::from_reader(cursor).map_err(|e| {
            TeeVerificationError::ParseError(format!("Failed to parse COSE structure: {}", e))
        })?;

        // COSE_Sign1 is a tagged array: Tag(18, [protected, unprotected, payload, signature])
        let cose_array = match cose {
            Value::Tag(18, inner) => match *inner {
                Value::Array(arr) => arr,
                _ => {
                    return Err(TeeVerificationError::ParseError(
                        "COSE_Sign1 must contain an array".to_string(),
                    ))
                }
            },
            Value::Array(arr) => arr, // Some implementations don't use the tag
            _ => {
                return Err(TeeVerificationError::ParseError(
                    "Invalid COSE_Sign1 structure".to_string(),
                ))
            }
        };

        if cose_array.len() < 4 {
            return Err(TeeVerificationError::ParseError(format!(
                "COSE_Sign1 array must have 4 elements, got {}",
                cose_array.len()
            )));
        }

        // Extract the payload (element 2) which contains the attestation document
        let payload_bytes = match &cose_array[2] {
            Value::Bytes(b) => b.clone(),
            _ => {
                return Err(TeeVerificationError::ParseError(
                    "COSE payload must be bytes".to_string(),
                ))
            }
        };

        // Parse the payload as CBOR map
        let payload_cursor = Cursor::new(&payload_bytes);
        let attestation_doc: Value = ciborium::from_reader(payload_cursor).map_err(|e| {
            TeeVerificationError::ParseError(format!("Failed to parse attestation payload: {}", e))
        })?;

        let doc_map = match attestation_doc {
            Value::Map(m) => m,
            _ => {
                return Err(TeeVerificationError::ParseError(
                    "Attestation document must be a map".to_string(),
                ))
            }
        };

        // Helper to extract bytes from a map
        let get_bytes =
            |map: &[(Value, Value)], key: &str| -> Result<Vec<u8>, TeeVerificationError> {
                for (k, v) in map {
                    if let Value::Text(k_str) = k {
                        if k_str == key {
                            return match v {
                                Value::Bytes(b) => Ok(b.clone()),
                                _ => Err(TeeVerificationError::ParseError(format!(
                                    "Field '{}' must be bytes",
                                    key
                                ))),
                            };
                        }
                    }
                }
                Err(TeeVerificationError::MissingField(key.to_string()))
            };

        // Helper to extract PCRs map
        let get_pcrs =
            |map: &[(Value, Value)]| -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), TeeVerificationError> {
                for (k, v) in map {
                    if let Value::Text(k_str) = k {
                        if k_str == "pcrs" {
                            if let Value::Map(pcr_map) = v {
                                let mut pcr0 = Vec::new();
                                let mut pcr1 = Vec::new();
                                let mut pcr2 = Vec::new();

                                for (pk, pv) in pcr_map {
                                    if let (Value::Integer(idx), Value::Bytes(data)) = (pk, pv) {
                                        let idx: i128 = (*idx).into();
                                        match idx {
                                            0 => pcr0 = data.clone(),
                                            1 => pcr1 = data.clone(),
                                            2 => pcr2 = data.clone(),
                                            _ => {}
                                        }
                                    }
                                }

                                return Ok((pcr0, pcr1, pcr2));
                            }
                        }
                    }
                }
                Err(TeeVerificationError::MissingField("pcrs".to_string()))
            };

        // Helper to extract timestamp
        let get_timestamp = |map: &[(Value, Value)]| -> Result<u64, TeeVerificationError> {
            for (k, v) in map {
                if let Value::Text(k_str) = k {
                    if k_str == "timestamp" {
                        return match v {
                            Value::Integer(i) => {
                                let val: i128 = (*i).into();
                                Ok(val as u64)
                            }
                            _ => Err(TeeVerificationError::ParseError(
                                "timestamp must be an integer".to_string(),
                            )),
                        };
                    }
                }
            }
            Err(TeeVerificationError::MissingField("timestamp".to_string()))
        };

        // Helper to extract certificate chain
        let get_cabundle = |map: &[(Value, Value)]| -> Result<Vec<Vec<u8>>, TeeVerificationError> {
            for (k, v) in map {
                if let Value::Text(k_str) = k {
                    if k_str == "cabundle" {
                        if let Value::Array(certs) = v {
                            let mut chain = Vec::new();
                            for cert in certs {
                                if let Value::Bytes(cert_bytes) = cert {
                                    chain.push(cert_bytes.clone());
                                }
                            }
                            return Ok(chain);
                        }
                    }
                }
            }
            Ok(Vec::new()) // Certificate chain is optional
        };

        // Extract fields from attestation document
        let (pcr0, pcr1, pcr2) = get_pcrs(&doc_map)?;
        let user_data = get_bytes(&doc_map, "user_data").unwrap_or_default();
        let public_key = get_bytes(&doc_map, "public_key").ok();
        let nonce = get_bytes(&doc_map, "nonce").ok();
        let timestamp = get_timestamp(&doc_map)?;
        let certificate_chain = get_cabundle(&doc_map)?;

        Ok(Self {
            raw_document,
            pcr0,
            pcr1,
            pcr2,
            user_data,
            public_key,
            nonce,
            certificate_chain,
            timestamp,
        })
    }

    /// Returns the enclave image hash (PCR0) as a hex string.
    pub fn pcr0_hex(&self) -> String {
        hex::encode(&self.pcr0)
    }

    /// Validates the basic structure of the document.
    pub fn validate(&self) -> Result<(), String> {
        if self.raw_document.is_empty() {
            return Err("Raw document cannot be empty".to_string());
        }

        // Validate PCR sizes (must be exactly 48 bytes / SHA-384)
        if self.pcr0.len() != 48 {
            return Err(format!(
                "PCR0 must be exactly 48 bytes, got {}",
                self.pcr0.len()
            ));
        }
        if self.pcr1.len() != 48 {
            return Err(format!(
                "PCR1 must be exactly 48 bytes, got {}",
                self.pcr1.len()
            ));
        }
        if self.pcr2.len() != 48 {
            return Err(format!(
                "PCR2 must be exactly 48 bytes, got {}",
                self.pcr2.len()
            ));
        }

        // Check PCR0 is not all zeros
        if self.pcr0.iter().all(|&b| b == 0) {
            return Err("PCR0 cannot be all zeros".to_string());
        }

        if self.user_data.is_empty() {
            return Err("User data cannot be empty (must contain data hash)".to_string());
        }

        if self.user_data.len() > 512 {
            return Err("User data exceeds maximum size of 512 bytes".to_string());
        }

        if self.certificate_chain.is_empty() {
            return Err("Certificate chain cannot be empty".to_string());
        }

        Ok(())
    }
}

// ============================================================================
// Intel SGX Quote
// ============================================================================

/// Intel SGX quote for remote attestation.
///
/// SGX quotes are signed statements from the Intel Attestation Service (IAS)
/// or a DCAP (Data Center Attestation Primitives) verifier that attest to
/// the identity and integrity of an SGX enclave.
///
/// # Key Fields
///
/// - **MRENCLAVE**: Hash of the enclave's initial code and data (256-bit)
/// - **MRSIGNER**: Hash of the enclave signer's public key
/// - **Report Data**: User-provided data (64 bytes)
///
/// # Verification
///
/// SGX quotes can be verified in two ways:
/// 1. **EPID-based**: Send to Intel Attestation Service (IAS) for verification
/// 2. **DCAP-based**: Verify locally using Intel's DCAP libraries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxQuote {
    /// Raw quote bytes as produced by the SGX hardware.
    pub raw_quote: Vec<u8>,

    /// MRENCLAVE: Hash of the enclave's code and initial data.
    ///
    /// This uniquely identifies the enclave code.
    /// Must be exactly 32 bytes (SHA-256).
    pub mr_enclave: Vec<u8>,

    /// MRSIGNER: Hash of the enclave signer's public key.
    ///
    /// Identifies who signed the enclave.
    /// Must be exactly 32 bytes (SHA-256).
    pub mr_signer: Vec<u8>,

    /// ISV Product ID: Enclave's product identifier.
    pub isv_prod_id: u16,

    /// ISV SVN: Enclave's security version number.
    pub isv_svn: u16,

    /// Report data: User-defined data included in the quote.
    ///
    /// For Willow indexers, the first 32 bytes contain the indexed data hash.
    /// Must be exactly 64 bytes.
    pub report_data: Vec<u8>,

    /// Quote type: EPID or DCAP.
    pub quote_type: SgxQuoteType,

    /// Attestation verification report from Intel (for EPID quotes).
    pub ias_report: Option<IasReport>,

    /// DCAP verification data (for DCAP quotes).
    pub dcap_data: Option<DcapVerificationData>,
}

impl SgxQuote {
    /// Returns the MRENCLAVE as a hex string.
    pub fn mr_enclave_hex(&self) -> String {
        hex::encode(&self.mr_enclave)
    }

    /// Extracts the data hash from the report data.
    ///
    /// The first 32 bytes of report_data contain the indexed data hash.
    /// Returns None if report_data is too short.
    pub fn extract_data_hash(&self) -> Option<[u8; 32]> {
        if self.report_data.len() >= 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&self.report_data[0..32]);
            Some(hash)
        } else {
            None
        }
    }

    /// Validates the basic structure of the quote.
    pub fn validate(&self) -> Result<(), String> {
        if self.raw_quote.is_empty() {
            return Err("Raw quote cannot be empty".to_string());
        }

        // Validate MRENCLAVE size (must be exactly 32 bytes)
        if self.mr_enclave.len() != 32 {
            return Err(format!(
                "MRENCLAVE must be exactly 32 bytes, got {}",
                self.mr_enclave.len()
            ));
        }

        // Validate MRSIGNER size (must be exactly 32 bytes)
        if self.mr_signer.len() != 32 {
            return Err(format!(
                "MRSIGNER must be exactly 32 bytes, got {}",
                self.mr_signer.len()
            ));
        }

        // Validate report_data size (must be exactly 64 bytes)
        if self.report_data.len() != 64 {
            return Err(format!(
                "Report data must be exactly 64 bytes, got {}",
                self.report_data.len()
            ));
        }

        // Check MRENCLAVE is not all zeros
        if self.mr_enclave.iter().all(|&b| b == 0) {
            return Err("MRENCLAVE cannot be all zeros".to_string());
        }

        match self.quote_type {
            SgxQuoteType::Epid => {
                if self.ias_report.is_none() {
                    return Err("IAS report required for EPID quotes".to_string());
                }
            }
            SgxQuoteType::Dcap => {
                if self.dcap_data.is_none() {
                    return Err("DCAP data required for DCAP quotes".to_string());
                }
            }
        }

        Ok(())
    }
}

/// SGX quote type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SgxQuoteType {
    /// EPID-based attestation (requires Intel Attestation Service).
    Epid,
    /// DCAP-based attestation (local verification with PCCS).
    Dcap,
}

/// Intel Attestation Service (IAS) report for EPID quotes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IasReport {
    /// The attestation verification report body (JSON).
    pub report_body: String,

    /// IAS signature over the report body.
    pub signature: Vec<u8>,

    /// IAS signing certificate chain.
    pub certificate_chain: Vec<String>,
}

/// DCAP verification data for local attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcapVerificationData {
    /// Collateral data for verification.
    pub collateral: Vec<u8>,

    /// Quote verification result.
    pub verification_result: u32,

    /// Supplemental data from verification.
    pub supplemental_data: Option<Vec<u8>>,
}

// ============================================================================
// Verification Results and Errors
// ============================================================================

/// Result of verifying a TEE attestation.
///
/// Contains the verified claims from the attestation that can be trusted
/// after successful verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedTeeAttestation {
    /// The TEE type that was verified.
    pub tee_type: TeeType,

    /// Verified enclave image hash (PCR0 or MRENCLAVE).
    pub enclave_image_hash: Vec<u8>,

    /// Verified data hash from the attestation.
    pub data_hash: [u8; 32],

    /// Timestamp from inside the enclave (Unix epoch seconds).
    ///
    /// Note: AWS Nitro provides timestamps in milliseconds, which are
    /// converted to seconds for consistency with SGX and other timestamps.
    pub timestamp: u64,

    /// Block range covered by this attestation.
    pub block_range: (u64, u64),

    /// When the verification was performed (Unix epoch seconds).
    pub verified_at: u64,
}

/// Errors that can occur during TEE attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TeeVerificationError {
    /// Failed to parse the attestation document.
    ParseError(String),

    /// Certificate chain verification failed.
    CertificateError(String),

    /// Signature verification failed.
    SignatureError(String),

    /// Enclave image hash is not in the approved list.
    UnapprovedEnclave {
        enclave_hash: String,
        tee_type: TeeType,
    },

    /// Data hash in attestation doesn't match submitted data.
    DataHashMismatch {
        expected: String,
        attestation: String,
    },

    /// Attestation timestamp is outside acceptable range.
    TimestampError(String),

    /// TEE type not supported.
    UnsupportedTeeType(TeeType),

    /// Missing required field in attestation.
    MissingField(String),

    /// Generic verification failure.
    VerificationFailed(String),

    /// Nonce mismatch - attestation contains wrong or missing nonce.
    NonceMismatch {
        expected: String,
        attestation: String,
    },

    /// Replay attack detected - nonce has already been used.
    NonceReplay { nonce: String },

    /// Rate limit exceeded - too many requests, try again later.
    RateLimitExceeded { message: String },

    /// SGX TCB (Trusted Computing Base) status issue.
    /// Platform may need security updates.
    TcbStatusError { status: String, message: String },

    /// Attestation has expired (too old).
    /// This is checked against `max_attestation_age_secs` configuration.
    ExpiredAttestation {
        /// Timestamp from the attestation (Unix epoch seconds).
        attestation_time: u64,
        /// Current time when verification was attempted (Unix epoch seconds).
        current_time: u64,
        /// Maximum allowed age configured (seconds).
        max_age_secs: u64,
    },
}

impl fmt::Display for TeeVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeeVerificationError::ParseError(msg) => {
                write!(f, "Failed to parse attestation: {}", msg)
            }
            TeeVerificationError::CertificateError(msg) => {
                write!(f, "Certificate verification failed: {}", msg)
            }
            TeeVerificationError::SignatureError(msg) => {
                write!(f, "Signature verification failed: {}", msg)
            }
            TeeVerificationError::UnapprovedEnclave {
                enclave_hash,
                tee_type,
            } => {
                write!(
                    f,
                    "Enclave {} is not approved for {:?}",
                    enclave_hash, tee_type
                )
            }
            TeeVerificationError::DataHashMismatch {
                expected,
                attestation,
            } => {
                write!(
                    f,
                    "Data hash mismatch: expected {}, attestation contains {}",
                    expected, attestation
                )
            }
            TeeVerificationError::TimestampError(msg) => {
                write!(f, "Timestamp validation failed: {}", msg)
            }
            TeeVerificationError::UnsupportedTeeType(tee_type) => {
                write!(f, "TEE type {:?} is not supported", tee_type)
            }
            TeeVerificationError::MissingField(field) => {
                write!(f, "Missing required field: {}", field)
            }
            TeeVerificationError::VerificationFailed(msg) => {
                write!(f, "Verification failed: {}", msg)
            }
            TeeVerificationError::NonceMismatch {
                expected,
                attestation,
            } => {
                write!(
                    f,
                    "Nonce mismatch: expected {}, attestation contains {}",
                    expected, attestation
                )
            }
            TeeVerificationError::NonceReplay { nonce } => {
                write!(
                    f,
                    "Replay attack detected: nonce {} has already been used",
                    nonce
                )
            }
            TeeVerificationError::RateLimitExceeded { message } => {
                write!(f, "Rate limit exceeded: {}", message)
            }
            TeeVerificationError::TcbStatusError { status, message } => {
                write!(f, "SGX TCB status error ({}): {}", status, message)
            }
            TeeVerificationError::ExpiredAttestation {
                attestation_time,
                current_time,
                max_age_secs,
            } => {
                let age_secs = current_time.saturating_sub(*attestation_time);
                write!(
                    f,
                    "Attestation expired: age {} seconds exceeds maximum {} seconds (attestation_time={}, current_time={})",
                    age_secs, max_age_secs, attestation_time, current_time
                )
            }
        }
    }
}

impl std::error::Error for TeeVerificationError {}

// ============================================================================
// Utility Functions
// ============================================================================

/// Performs constant-time comparison of two byte slices.
///
/// This function is designed to resist timing side-channel attacks by:
/// - Including length difference in the result (no early return on length mismatch)
/// - Iterating over the longer slice to prevent length-based timing inference
/// - Using XOR accumulation instead of short-circuit evaluation
///
/// # Security Note
/// The `#[inline(never)]` attribute prevents the compiler from inlining this
/// function, which could otherwise enable timing analysis through code elimination.
///
/// Returns `true` if the slices are equal in both length and content.
#[inline(never)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Include length difference in the result - this avoids early return timing leak
    // XOR of lengths is 0 only if they're equal
    let mut result: usize = a.len() ^ b.len();

    // Always iterate over the longer slice to prevent length-based timing attacks
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        // Use get() which returns None for out-of-bounds, then unwrap_or(0)
        // This ensures we always do the same operations regardless of actual lengths
        let a_byte = a.get(i).copied().unwrap_or(0);
        let b_byte = b.get(i).copied().unwrap_or(0);
        result |= (a_byte ^ b_byte) as usize;
    }

    // result == 0 only if lengths match AND all bytes match
    result == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_type_properties() {
        assert_eq!(TeeType::AwsNitro.enclave_hash_size(), 48);
        assert_eq!(TeeType::IntelSgx.enclave_hash_size(), 32);
        assert_eq!(TeeType::AmdSev.enclave_hash_size(), 48);

        assert!(TeeType::AwsNitro.is_supported());
        assert!(TeeType::IntelSgx.is_supported());
        assert!(!TeeType::AmdSev.is_supported());

        assert_eq!(TeeType::AwsNitro.name(), "AWS Nitro Enclaves");
        assert_eq!(TeeType::IntelSgx.name(), "Intel SGX");
    }

    #[test]
    fn test_tee_capability_validation() {
        // Valid Nitro capability
        let valid_nitro = TeeCapability {
            tee_type: TeeType::AwsNitro,
            enclave_image_hash: vec![1u8; 48],
            attestation_proof: vec![1, 2, 3, 4],
            attested_at: 1700000000,
        };
        assert!(valid_nitro.validate().is_ok());

        // Valid SGX capability
        let valid_sgx = TeeCapability {
            tee_type: TeeType::IntelSgx,
            enclave_image_hash: vec![1u8; 32],
            attestation_proof: vec![1, 2, 3, 4],
            attested_at: 1700000000,
        };
        assert!(valid_sgx.validate().is_ok());

        // Invalid: wrong hash size for Nitro
        let invalid_hash_size = TeeCapability {
            tee_type: TeeType::AwsNitro,
            enclave_image_hash: vec![1u8; 32], // Should be 48
            attestation_proof: vec![1, 2, 3, 4],
            attested_at: 1700000000,
        };
        assert!(invalid_hash_size.validate().is_err());

        // Invalid: empty attestation proof
        let empty_proof = TeeCapability {
            tee_type: TeeType::AwsNitro,
            enclave_image_hash: vec![1u8; 48],
            attestation_proof: vec![],
            attested_at: 1700000000,
        };
        assert!(empty_proof.validate().is_err());

        // Invalid: unsupported TEE type
        let unsupported = TeeCapability {
            tee_type: TeeType::AmdSev,
            enclave_image_hash: vec![1u8; 48],
            attestation_proof: vec![1, 2, 3, 4],
            attested_at: 1700000000,
        };
        assert!(unsupported.validate().is_err());
    }

    #[test]
    fn test_tee_attestation_validation() {
        let valid_nitro_doc = NitroAttestationDocument {
            raw_document: vec![1, 2, 3, 4],
            pcr0: vec![1u8; 48],
            pcr1: vec![2u8; 48],
            pcr2: vec![3u8; 48],
            user_data: vec![1u8; 32],
            public_key: None,
            nonce: None,
            certificate_chain: vec![vec![1, 2, 3]],
            timestamp: 1700000000,
        };

        let valid_attestation = TeeAttestation {
            tee_type: TeeType::AwsNitro,
            nitro_document: Some(valid_nitro_doc),
            sgx_quote: None,
            data_hash: [1u8; 32],
            timestamp: 1700000000,
            block_range: (1000, 2000),
        };
        assert!(valid_attestation.validate().is_ok());

        // Invalid: Nitro type but missing document
        let missing_doc = TeeAttestation {
            tee_type: TeeType::AwsNitro,
            nitro_document: None,
            sgx_quote: None,
            data_hash: [1u8; 32],
            timestamp: 1700000000,
            block_range: (1000, 2000),
        };
        assert!(missing_doc.validate().is_err());

        // Invalid: bad block range
        let bad_range = TeeAttestation {
            tee_type: TeeType::AwsNitro,
            nitro_document: Some(NitroAttestationDocument {
                raw_document: vec![1, 2, 3, 4],
                pcr0: vec![1u8; 48],
                pcr1: vec![2u8; 48],
                pcr2: vec![3u8; 48],
                user_data: vec![1u8; 32],
                public_key: None,
                nonce: None,
                certificate_chain: vec![vec![1, 2, 3]],
                timestamp: 1700000000,
            }),
            sgx_quote: None,
            data_hash: [1u8; 32],
            timestamp: 1700000000,
            block_range: (2000, 1000), // End before start
        };
        assert!(bad_range.validate().is_err());

        // Invalid: zero data hash
        let zero_hash = TeeAttestation {
            tee_type: TeeType::AwsNitro,
            nitro_document: Some(NitroAttestationDocument {
                raw_document: vec![1, 2, 3, 4],
                pcr0: vec![1u8; 48],
                pcr1: vec![2u8; 48],
                pcr2: vec![3u8; 48],
                user_data: vec![1u8; 32],
                public_key: None,
                nonce: None,
                certificate_chain: vec![vec![1, 2, 3]],
                timestamp: 1700000000,
            }),
            sgx_quote: None,
            data_hash: [0u8; 32],
            timestamp: 1700000000,
            block_range: (1000, 2000),
        };
        assert!(zero_hash.validate().is_err());
    }

    #[test]
    fn test_nitro_document_validation() {
        let valid = NitroAttestationDocument {
            raw_document: vec![1, 2, 3, 4],
            pcr0: vec![1u8; 48],
            pcr1: vec![2u8; 48],
            pcr2: vec![3u8; 48],
            user_data: vec![1u8; 32],
            public_key: None,
            nonce: None,
            certificate_chain: vec![vec![1, 2, 3]],
            timestamp: 1700000000,
        };
        assert!(valid.validate().is_ok());

        // Invalid: empty raw document
        let empty_raw = NitroAttestationDocument {
            raw_document: vec![],
            ..valid.clone()
        };
        assert!(empty_raw.validate().is_err());

        // Invalid: zero PCR0
        let zero_pcr = NitroAttestationDocument {
            pcr0: vec![0u8; 48],
            ..valid.clone()
        };
        assert!(zero_pcr.validate().is_err());

        // Invalid: empty user data
        let empty_user_data = NitroAttestationDocument {
            user_data: vec![],
            ..valid.clone()
        };
        assert!(empty_user_data.validate().is_err());

        // Invalid: user data too large
        let large_user_data = NitroAttestationDocument {
            user_data: vec![1u8; 600],
            ..valid.clone()
        };
        assert!(large_user_data.validate().is_err());

        // Invalid: empty certificate chain
        let empty_certs = NitroAttestationDocument {
            certificate_chain: vec![],
            ..valid.clone()
        };
        assert!(empty_certs.validate().is_err());

        // Invalid: wrong PCR0 size
        let wrong_size = NitroAttestationDocument {
            pcr0: vec![1u8; 32], // Should be 48
            ..valid.clone()
        };
        assert!(wrong_size.validate().is_err());
    }

    #[test]
    fn test_sgx_quote_validation() {
        let valid = SgxQuote {
            raw_quote: vec![1, 2, 3, 4],
            mr_enclave: vec![1u8; 32],
            mr_signer: vec![2u8; 32],
            isv_prod_id: 1,
            isv_svn: 1,
            report_data: vec![1u8; 64],
            quote_type: SgxQuoteType::Epid,
            ias_report: Some(IasReport {
                report_body: "{}".to_string(),
                signature: vec![1, 2, 3],
                certificate_chain: vec!["cert".to_string()],
            }),
            dcap_data: None,
        };
        assert!(valid.validate().is_ok());

        // Invalid: EPID without IAS report
        let no_ias = SgxQuote {
            ias_report: None,
            ..valid.clone()
        };
        assert!(no_ias.validate().is_err());

        // Invalid: zero MRENCLAVE
        let zero_mr = SgxQuote {
            mr_enclave: vec![0u8; 32],
            ..valid.clone()
        };
        assert!(zero_mr.validate().is_err());

        // Invalid: wrong MRENCLAVE size
        let wrong_size = SgxQuote {
            mr_enclave: vec![1u8; 48], // Should be 32
            ..valid.clone()
        };
        assert!(wrong_size.validate().is_err());

        // Invalid: wrong report_data size
        let wrong_report_size = SgxQuote {
            report_data: vec![1u8; 32], // Should be 64
            ..valid.clone()
        };
        assert!(wrong_report_size.validate().is_err());
    }

    #[test]
    fn test_sgx_extract_data_hash() {
        let mut report_data = vec![0u8; 64];
        report_data[0..32].copy_from_slice(&[0xAB; 32]);

        let quote = SgxQuote {
            raw_quote: vec![1, 2, 3, 4],
            mr_enclave: vec![1u8; 32],
            mr_signer: vec![2u8; 32],
            isv_prod_id: 1,
            isv_svn: 1,
            report_data,
            quote_type: SgxQuoteType::Dcap,
            ias_report: None,
            dcap_data: Some(DcapVerificationData {
                collateral: vec![],
                verification_result: 0,
                supplemental_data: None,
            }),
        };

        let extracted = quote.extract_data_hash().unwrap();
        assert_eq!(extracted, [0xAB; 32]);
    }

    #[test]
    fn test_tee_attestation_enclave_hash() {
        // Nitro attestation
        let nitro_attestation = TeeAttestation {
            tee_type: TeeType::AwsNitro,
            nitro_document: Some(NitroAttestationDocument {
                raw_document: vec![1, 2, 3, 4],
                pcr0: vec![0xAB; 48],
                pcr1: vec![2u8; 48],
                pcr2: vec![3u8; 48],
                user_data: vec![1u8; 32],
                public_key: None,
                nonce: None,
                certificate_chain: vec![vec![1, 2, 3]],
                timestamp: 1700000000,
            }),
            sgx_quote: None,
            data_hash: [1u8; 32],
            timestamp: 1700000000,
            block_range: (1000, 2000),
        };
        let hash = nitro_attestation.enclave_image_hash().unwrap();
        assert_eq!(hash, vec![0xAB; 48]);

        // SGX attestation
        let sgx_attestation = TeeAttestation {
            tee_type: TeeType::IntelSgx,
            nitro_document: None,
            sgx_quote: Some(SgxQuote {
                raw_quote: vec![1, 2, 3, 4],
                mr_enclave: vec![0xCD; 32],
                mr_signer: vec![2u8; 32],
                isv_prod_id: 1,
                isv_svn: 1,
                report_data: vec![1u8; 64],
                quote_type: SgxQuoteType::Dcap,
                ias_report: None,
                dcap_data: Some(DcapVerificationData {
                    collateral: vec![],
                    verification_result: 0,
                    supplemental_data: None,
                }),
            }),
            data_hash: [1u8; 32],
            timestamp: 1700000000,
            block_range: (1000, 2000),
        };
        let hash = sgx_attestation.enclave_image_hash().unwrap();
        assert_eq!(hash, vec![0xCD; 32]);
    }

    #[test]
    fn test_tee_verification_error_display() {
        let err = TeeVerificationError::UnapprovedEnclave {
            enclave_hash: "abc123".to_string(),
            tee_type: TeeType::AwsNitro,
        };
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("AwsNitro"));

        let err = TeeVerificationError::DataHashMismatch {
            expected: "expected".to_string(),
            attestation: "actual".to_string(),
        };
        assert!(err.to_string().contains("expected"));
        assert!(err.to_string().contains("actual"));
    }

    #[test]
    fn test_tee_type_serialization() {
        let types = vec![TeeType::AwsNitro, TeeType::IntelSgx, TeeType::AmdSev];

        for tee_type in types {
            let serialized = serde_json::to_string(&tee_type).unwrap();
            let deserialized: TeeType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(tee_type, deserialized);
        }
    }
}
