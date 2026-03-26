//! Fundamental types for BOLT message encoding.

use super::BoltError;
use super::wire::WireFormat;

/// Maximum Lightning message size (2-byte length prefix limit).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of a channel ID in bytes.
pub const CHANNEL_ID_SIZE: usize = 32;

/// Size of a chain hash (SHA256).
pub const CHAIN_HASH_SIZE: usize = 32;

/// A 32-byte channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelId(pub [u8; CHANNEL_ID_SIZE]);

impl ChannelId {
    /// Special all-zero channel ID indicating "all channels" (for errors)
    /// or "not channel-specific" (for warnings).
    pub const ALL: Self = Self([0u8; CHANNEL_ID_SIZE]);

    /// Creates a channel ID from a byte array.
    #[must_use]
    pub const fn new(bytes: [u8; CHANNEL_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the channel ID as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CHANNEL_ID_SIZE] {
        &self.0
    }
}

/// A variable-length unsigned integer similar to Bitcoin's `CompactSize`
/// encoding, but big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigSize(pub u64);

impl BigSize {
    /// Creates a `BigSize` from a `u64` value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner `u64` value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the encoded length of this `BigSize` value.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // BigSize always encodes to at least 1 byte
    pub const fn len(self) -> usize {
        if self.value() < 0xfd {
            1
        } else if self.value() < 0x1_0000 {
            3
        } else if self.value() < 0x1_0000_0000 {
            5
        } else {
            9
        }
    }
}

/// Reads a `[u16:len][len*byte]` variable-length field, advancing past both.
///
/// # Errors
///
/// Returns `Truncated` if there are fewer bytes than the declared length.
pub fn read_var_bytes(data: &mut &[u8]) -> Result<Vec<u8>, BoltError> {
    let len = u16::read(data)? as usize;
    if data.len() < len {
        return Err(BoltError::Truncated {
            expected: len,
            actual: data.len(),
        });
    }
    let bytes = data[..len].to_vec();
    *data = &data[len..];
    Ok(bytes)
}

/// Writes a `[u16:len][len*byte]` variable-length field.
pub fn write_var_bytes(data: &[u8], out: &mut Vec<u8>) {
    #[allow(clippy::cast_possible_truncation)] // Checked in constructors
    (data.len() as u16).write(out);
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigsize_new() {
        let bs = BigSize::new(42);
        assert_eq!(bs.0, 42);
        assert_eq!(bs.value(), 42);
    }

    #[test]
    fn bigsize_value() {
        for v in [0u64, 1, 252, 253, 65535, 65536, u64::MAX] {
            assert_eq!(BigSize::new(v).value(), v);
        }
    }

    #[test]
    fn read_var_bytes_empty_field() {
        let mut data: &[u8] = &[0x00, 0x00];
        let result = read_var_bytes(&mut data).unwrap();
        assert_eq!(result, Vec::<u8>::new());
        assert!(data.is_empty());
    }

    #[test]
    fn read_var_bytes_valid() {
        let mut data: &[u8] = &[0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let result = read_var_bytes(&mut data).unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc]);
        assert!(data.is_empty());
    }

    #[test]
    fn read_var_bytes_advances_cursor() {
        let mut data: &[u8] = &[0x00, 0x02, 0xaa, 0xbb, 0xff, 0xff];
        let result = read_var_bytes(&mut data).unwrap();
        assert_eq!(result, vec![0xaa, 0xbb]);
        assert_eq!(data, &[0xff, 0xff]);
    }

    #[test]
    fn read_var_bytes_truncated_length() {
        let mut data: &[u8] = &[0x00];
        assert_eq!(
            read_var_bytes(&mut data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn read_var_bytes_truncated_data() {
        let mut data: &[u8] = &[0x00, 0x05, 0xaa, 0xbb];
        assert_eq!(
            read_var_bytes(&mut data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2
            })
        );
    }

    #[test]
    fn write_var_bytes_roundtrip() {
        let original = vec![0xaa, 0xbb];
        let mut out = Vec::new();
        write_var_bytes(&original, &mut out);

        let mut cursor: &[u8] = &out;
        let decoded = read_var_bytes(&mut cursor).unwrap();
        assert_eq!(decoded, original);
        assert!(cursor.is_empty());
    }

    #[test]
    fn channel_id_all_is_zeros() {
        assert_eq!(ChannelId::ALL.0, [0u8; CHANNEL_ID_SIZE]);
    }

    #[test]
    fn channel_id_new() {
        let bytes = [0x42u8; CHANNEL_ID_SIZE];
        let id = ChannelId::new(bytes);
        assert_eq!(id.0, bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn channel_id_default_is_all() {
        assert_eq!(ChannelId::default(), ChannelId::ALL);
    }
}
