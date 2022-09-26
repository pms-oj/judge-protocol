use serde::{Serialize, Deserialize};
use md5::{Md5, Digest};

use super::constants::MAGIC;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[repr(u16)]
pub enum Command {
    HANDSHAKE = 0x00,
    // Client
    VERIFY_TOKEN = 0x01,
    GET_LOGIN = 0x02, // with key exchange by ECDH
    GET_JUDGE = 0x03,
    // Server
    REQ_VERIFY_TOKEN = 0xF1,
    REQ_LOGIN = 0xF2,
    REQ_JUDGE = 0xF3,
    UNKNOWN = 0xFF,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(packed)]
pub struct PacketHeader {
    magic: u32, // 4 bytes
    pub command: Command, // 2 bytes
    pub length: u32, // 4 bytes
}

impl PacketHeader {
    pub fn check_magic(&self) -> bool {
        self.magic == MAGIC
    }
}

const_assert!(std::mem::size_of::<Command>() == 2);
const_assert!(std::mem::size_of::<PacketHeader>() == 10);

// header || body
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PacketHeady {
    pub header: PacketHeader,
    pub body: Vec<u8>,
}

impl PacketHeady {
    pub fn checksum(&self) -> [u8; 16] {
        let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
        let mut hasher = Md5::new();
        hasher.update(encoded);
        let tmp = hasher.finalize();
        let r: &[u8;16] = tmp.as_ref();
        r.clone()
    }

    pub fn make_packet(command: Command, body: Vec<u8>) -> Self {
        let header = PacketHeader {
            magic: MAGIC,
            command,
            length: (body.len() as u32), // safe size_of::<usize>() >= 4
        };
        PacketHeady {
            header,
            body,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Packet {
    pub heady: PacketHeady,
    pub checksum: [u8; 16], // md5 checksum of (header || body)
}

impl Packet {
    pub fn make_packet(command: Command, body: Vec<u8>) -> Self {
        Self::from_heady(PacketHeady::make_packet(command, body))
    }

    pub fn from_heady(heady: PacketHeady) -> Self {
        let check = heady.checksum();
        Self {
            heady: heady,
            checksum: check,
        }
    }

    pub fn verify(&self) -> bool {
        self.heady.checksum() == self.checksum
    }
}