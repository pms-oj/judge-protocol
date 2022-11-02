use async_std::channel::Sender;
use async_std::io::prelude::*;
use s2n_quic::stream::{BidirectionalStream, ReceiveStream, SendStream};
use serde::{Deserialize, Serialize};

use super::constants::{HEADER_SIZE, MAGIC};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum Command {
    Handshake = 0x0000,
    // Client
    VerifyToken = 0x0001,
    GetLogin = 0x0002, // with key exchange by ECDH
    ReqJudge = 0x0003,
    ReqJudgev2 = 0x0F03,
    GetJudgeStateUpdate = 0x0004,
    // Server
    ReqVerifyToken = 0xF001,
    ReqLogin = 0xF002,
    GetJudge = 0xF003,
    GetJudgev2 = 0xFF03,
    TestCaseUpdate = 0xF004,
    TestCaseEnd = 0xF005,
    // General
    Unknown = 0xFFFF,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[repr(C, packed)]
pub struct PacketHeader {
    magic: u32,           // 4 bytes
    pub command: Command, // 4 bytes
}

impl PacketHeader {
    pub fn check_magic(&self) -> bool {
        self.magic == MAGIC
    }
}

const_assert!(std::mem::size_of::<Command>() == 4);
const_assert!(std::mem::size_of::<PacketHeader>() == HEADER_SIZE);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Packet {
    header: PacketHeader,
    pub body: Vec<u8>,
}

impl Packet {
    pub fn make_packet(command: Command, body: Vec<u8>) -> Self {
        Self {
            header: PacketHeader {
                magic: MAGIC,
                command,
            },
            body,
        }
    }

    pub async fn send(&self, stream: &mut BidirectionalStream) -> async_std::io::Result<()> {
        stream
            .write_all(
                &bincode::serialize(&self)
                    .expect("Failed to serialize a packet when running bincode::serialize"),
            )
            .await?;
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self)
            .expect("Failed to serialize a packet when running bincode::serialize")
    }

    pub async fn from_stream(stream: &mut BidirectionalStream) -> async_std::io::Result<Self> {
        if let Some(data) = stream.receive().await? {
            Ok(bincode::deserialize(&data).expect(
                "Failed to deserialize a received packet when running bincode::deserialize",
            ))
        } else {
            Err(async_std::io::Error::from(
                async_std::io::ErrorKind::InvalidData,
            ))
        }
    }
}
