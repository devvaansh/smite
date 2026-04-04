//! BOLT 2 `update_fail_htlc` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// TLV type for attribution data.
const TLV_ATTRIBUTION_DATA: u64 = 1;

/// Maximum number of hops for failure attribution.
const ATTRIBUTION_MAX_HOPS: usize = 20;

/// Number of truncated HMACs in attribution data.
const ATTRIBUTION_NUM_HMACS: usize = 210;

/// Size of each truncated HMAC in bytes.
const TRUNCATED_HMAC_SIZE: usize = 4;

/// Total wire size of attribution data: `20 * 4 + 210 * 4` = 920 bytes.
const ATTRIBUTION_DATA_SIZE: usize =
    ATTRIBUTION_MAX_HOPS * 4 + ATTRIBUTION_NUM_HMACS * TRUNCATED_HMAC_SIZE;

/// A 4-byte truncated SHA-256 HMAC used in failure attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TruncatedHmac(pub [u8; TRUNCATED_HMAC_SIZE]);

impl WireFormat for TruncatedHmac {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let bytes: [u8; TRUNCATED_HMAC_SIZE] = WireFormat::read(data)?;
        Ok(Self(bytes))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.0.write(out);
    }
}

/// Attribution data for failure/fulfill attribution (TLV type 1).
///
/// Fixed-size structure (920 bytes) containing per-hop hold times and
/// truncated HMACs for attribution verification, always padded to the
/// maximum of 20 hops.  Defined in the BOLT 4 attribution proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionData {
    /// Per-hop hold times in milliseconds.
    pub htlc_hold_times: [u32; ATTRIBUTION_MAX_HOPS],
    /// Truncated HMACs for hop-by-hop verification.
    pub truncated_hmacs: [TruncatedHmac; ATTRIBUTION_NUM_HMACS],
}

impl AttributionData {
    /// Total wire size in bytes (920).
    pub const SIZE: usize = ATTRIBUTION_DATA_SIZE;

    /// Encodes attribution data to bytes for inclusion in a TLV value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        for &t in &self.htlc_hold_times {
            t.write(&mut out);
        }
        for hmac in &self.truncated_hmacs {
            hmac.write(&mut out);
        }
        out
    }

    /// Decodes attribution data from the raw TLV value bytes.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the data is not exactly 920 bytes.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        if data.len() != Self::SIZE {
            return Err(BoltError::Truncated {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }
        let mut cursor = data;
        let mut htlc_hold_times = [0u32; ATTRIBUTION_MAX_HOPS];
        for ht in &mut htlc_hold_times {
            *ht = WireFormat::read(&mut cursor)?;
        }
        let mut truncated_hmacs = [TruncatedHmac::default(); ATTRIBUTION_NUM_HMACS];
        for hmac in &mut truncated_hmacs {
            *hmac = WireFormat::read(&mut cursor)?;
        }
        Ok(Self {
            htlc_hold_times,
            truncated_hmacs,
        })
    }
}

/// BOLT 2 `update_fail_htlc` message (type 131).
///
/// Sent to fail an HTLC back to the sender.  The `reason` field contains an
/// encrypted failure message that is relayed back along the payment path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFailHtlc {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The HTLC ID being failed.
    pub id: u64,
    /// Encrypted reason for the failure, relayed back to the sender.
    pub reason: Vec<u8>,
    /// Optional TLV extensions.
    pub tlvs: UpdateFailHtlcTlvs,
}

/// TLV extensions for the `update_fail_htlc` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateFailHtlcTlvs {
    /// Attribution data for failure attribution (TLV type 1).
    pub attribution_data: Option<AttributionData>,
}

impl UpdateFailHtlc {
    /// Encodes to wire format (without message type prefix).
    ///
    /// # Panics
    ///
    /// Panics if `reason` is longer than `u16::MAX` bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        assert!(
            u16::try_from(self.reason.len()).is_ok(),
            "reason length {} exceeds u16::MAX",
            self.reason.len()
        );

        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.id.write(&mut out);
        self.reason.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(attr) = &self.tlvs.attribution_data {
            tlv_stream.add(TLV_ATTRIBUTION_DATA, attr.encode());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short, or TLV errors
    /// if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = WireFormat::read(&mut cursor)?;
        let id = WireFormat::read(&mut cursor)?;
        let reason = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // attribution_data is type 1 (odd), so no known even types
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = UpdateFailHtlcTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            id,
            reason,
            tlvs,
        })
    }
}

impl UpdateFailHtlcTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if `attribution_data` has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let attribution_data = stream
            .get(TLV_ATTRIBUTION_DATA)
            .map(AttributionData::decode)
            .transpose()?;
        Ok(Self { attribution_data })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    fn sample_msg() -> UpdateFailHtlc {
        UpdateFailHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 42,
            reason: vec![0xde, 0xad, 0xbe, 0xef],
            tlvs: UpdateFailHtlcTlvs::default(),
        }
    }

    #[test]
    fn encode_field_sizes() {
        let msg = UpdateFailHtlc {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            id: 1,
            reason: vec![0xaa, 0xbb],
            tlvs: UpdateFailHtlcTlvs::default(),
        };
        let encoded = msg.encode();
        // channel_id(32) + id(8) + len(2) + reason(2) = 44
        assert_eq!(encoded.len(), 44);
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = UpdateFailHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_empty_reason() {
        let original = UpdateFailHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 7,
            reason: vec![],
            tlvs: UpdateFailHtlcTlvs::default(),
        };
        let encoded = original.encode();
        let decoded = UpdateFailHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_attribution_data() {
        let mut msg = sample_msg();
        msg.tlvs.attribution_data = Some(AttributionData {
            htlc_hold_times: [100; 20],
            truncated_hmacs: [TruncatedHmac([0xaa; 4]); 210],
        });
        let encoded = msg.encode();
        let decoded = UpdateFailHtlc::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_truncated_attribution_data() {
        let msg = sample_msg();
        let mut encoded = msg.encode();
        // Append a TLV type 1 with only 100 bytes (should be 920)
        encoded.push(0x01); // type
        encoded.push(0x64); // length = 100
        encoded.extend_from_slice(&[0x00; 100]);
        assert_eq!(
            UpdateFailHtlc::decode(&encoded),
            Err(BoltError::Truncated {
                expected: AttributionData::SIZE,
                actual: 100
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let mut msg = sample_msg();
        let mut encoded = msg.encode();
        // Append an unknown odd TLV (type 3, len 2, value 0xffff)
        encoded.extend_from_slice(&[0x03, 0x02, 0xff, 0xff]);
        let decoded = UpdateFailHtlc::decode(&encoded).unwrap();
        msg.tlvs = UpdateFailHtlcTlvs::default();
        assert_eq!(decoded.channel_id, msg.channel_id);
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.reason, msg.reason);
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let mut encoded = sample_msg().encode();
        // Append an unknown even TLV (type 2, len 1, value 0x00)
        encoded.extend_from_slice(&[0x02, 0x01, 0x00]);
        assert!(matches!(
            UpdateFailHtlc::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        ));
    }

    #[test]
    #[should_panic(expected = "reason length")]
    fn encode_panics_on_oversized_reason() {
        let msg = UpdateFailHtlc {
            channel_id: ChannelId::new([0x00; CHANNEL_ID_SIZE]),
            id: 0,
            reason: vec![0x00; u16::MAX as usize + 1],
            tlvs: UpdateFailHtlcTlvs::default(),
        };
        let _ = msg.encode();
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            UpdateFailHtlc::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_id() {
        // Full channel_id (32 bytes) + only 4 bytes of id
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 4]);
        assert_eq!(
            UpdateFailHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_len() {
        // Full channel_id (32 bytes) + full id (8 bytes) + only 1 byte of len
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 8]);
        data.push(0x00);
        assert_eq!(
            UpdateFailHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_reason() {
        // Full channel_id (32 bytes) + full id (8 bytes) + len = 16 + only 5 bytes
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 8]);
        data.extend_from_slice(&[0x00, 0x10]); // len = 16
        data.extend_from_slice(b"short"); // only 5 bytes
        assert_eq!(
            UpdateFailHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 16,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            UpdateFailHtlc::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
