use alloc::vec::Vec;
use core::cmp;

use ironrdp_core::{DecodeResult, cast_length, invalid_field_err};
use tracing::error;

use crate::pdu::{DataFirstPdu, DataPdu, DrdynvcDataPdu};

#[derive(Debug, PartialEq)]
pub(crate) struct CompleteData {
    total_size: usize,
    data: Vec<u8>,
    maximum_size: usize,
}

/// Maximum incoming dynamic-channel message, including fragmented messages.
/// 64 MiB permits uncompressed 4K RGBA while bounding the u32 wire length.
const MAX_DYNAMIC_CHANNEL_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

impl CompleteData {
    pub(crate) fn new() -> Self {
        Self {
            total_size: 0,
            data: Vec::new(),
            maximum_size: MAX_DYNAMIC_CHANNEL_MESSAGE_SIZE,
        }
    }

    pub(crate) fn process_data(&mut self, pdu: DrdynvcDataPdu) -> DecodeResult<Option<Vec<u8>>> {
        match pdu {
            DrdynvcDataPdu::DataFirst(data_first) => self.process_data_first_pdu(data_first),
            DrdynvcDataPdu::Data(data) => self.process_data_pdu(data),
        }
    }

    fn process_data_first_pdu(&mut self, data_first: DataFirstPdu) -> DecodeResult<Option<Vec<u8>>> {
        let total_data_size: DecodeResult<_> = cast_length!("DataFirstPdu::length", data_first.length());
        let total_data_size = total_data_size?;
        if total_data_size > self.maximum_size || data_first.data().len() > total_data_size {
            self.clear();
            return Err(invalid_field_err!(
                "DVC message",
                "length",
                "message exceeds reassembly bounds"
            ));
        }
        if self.total_size != 0 || !self.data.is_empty() {
            error!("Incomplete DVC message, it will be skipped");

            self.clear();
        }

        if total_data_size == data_first.data().len() {
            Ok(Some(data_first.into_data()))
        } else {
            self.total_size = total_data_size;
            self.data = data_first.into_data();

            Ok(None)
        }
    }

    fn process_data_pdu(&mut self, mut data: DataPdu) -> DecodeResult<Option<Vec<u8>>> {
        if data.data().len() > self.maximum_size {
            self.clear();
            return Err(invalid_field_err!(
                "DVC message",
                "length",
                "message exceeds reassembly limit"
            ));
        }
        if self.total_size == 0 && self.data.is_empty() {
            // message is not fragmented
            return Ok(Some(data.into_data()));
        }

        // The message is fragmented and needs to be reassembled.
        match self.data.len().checked_add(data.data().len()) {
            Some(actual_data_length) if actual_data_length <= self.maximum_size => {
                match actual_data_length.cmp(&(self.total_size)) {
                    cmp::Ordering::Less => {
                        // this is one of the fragmented messages, just append it
                        self.data.append(data.data_mut());
                        Ok(None)
                    }
                    cmp::Ordering::Equal => {
                        // this is the last fragmented message, need to return the whole reassembled message
                        self.total_size = 0;
                        self.data.append(data.data_mut());
                        Ok(Some(core::mem::take(&mut self.data)))
                    }
                    cmp::Ordering::Greater => {
                        error!("Actual DVC message size is grater than expected total DVC message size");
                        self.clear();
                        Err(invalid_field_err!(
                            "DVC message",
                            "length",
                            "fragments exceed declared length"
                        ))
                    }
                }
            }
            _ => {
                self.clear();
                Err(invalid_field_err!(
                    "DVC message",
                    "length",
                    "fragments exceed reassembly limit"
                ))
            }
        }
    }

    fn clear(&mut self) {
        self.total_size = 0;
        self.data = Vec::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_large_declared_length_before_retaining_first_fragment() {
        let mut complete = CompleteData::new();
        assert!(
            complete
                .process_data_first_pdu(DataFirstPdu::new(
                    1,
                    (MAX_DYNAMIC_CHANNEL_MESSAGE_SIZE + 1) as u32,
                    alloc::vec![1]
                ))
                .is_err()
        );
        assert!(complete.data.is_empty());
        assert_eq!(complete.total_size, 0);
    }

    #[test]
    fn fragments_and_unfragmented_messages_share_the_limit() {
        let mut complete = CompleteData {
            maximum_size: 8,
            ..CompleteData::new()
        };
        assert!(complete.process_data_pdu(DataPdu::new(1, alloc::vec![0; 9])).is_err());
        assert!(
            complete
                .process_data_first_pdu(DataFirstPdu::new(1, 8, alloc::vec![1; 4]))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            complete
                .process_data_pdu(DataPdu::new(1, alloc::vec![2; 4]))
                .unwrap()
                .unwrap(),
            [1, 1, 1, 1, 2, 2, 2, 2]
        );
        assert!(complete.data.is_empty());
        assert_eq!(complete.total_size, 0);
    }

    #[test]
    fn overlong_first_and_continuation_fragments_reset_state() {
        let mut complete = CompleteData::new();
        assert!(
            complete
                .process_data_first_pdu(DataFirstPdu::new(1, 1, alloc::vec![0; 2]))
                .is_err()
        );
        assert!(
            complete
                .process_data_first_pdu(DataFirstPdu::new(1, 2, alloc::vec![0]))
                .unwrap()
                .is_none()
        );
        assert!(complete.process_data_pdu(DataPdu::new(1, alloc::vec![0; 2])).is_err());
        assert!(complete.data.is_empty());
        assert_eq!(complete.total_size, 0);
        assert_eq!(
            complete
                .process_data_pdu(DataPdu::new(1, alloc::vec![3]))
                .unwrap()
                .unwrap(),
            [3]
        );
    }

    #[test]
    fn complete_replacement_clears_previous_fragment_state() {
        let mut complete = CompleteData::new();
        assert!(
            complete
                .process_data_first_pdu(DataFirstPdu::new(1, 4, alloc::vec![0]))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            complete
                .process_data_first_pdu(DataFirstPdu::new(1, 1, alloc::vec![1]))
                .unwrap()
                .unwrap(),
            [1]
        );
        assert_eq!(complete.total_size, 0);
        assert_eq!(
            complete
                .process_data_pdu(DataPdu::new(1, alloc::vec![2]))
                .unwrap()
                .unwrap(),
            [2]
        );
    }
}
