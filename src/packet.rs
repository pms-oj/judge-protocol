use async_std::channel::Sender;
use async_std::io::prelude::*;
use async_std::io::BufReader;
use async_std::io::{Error, ErrorKind};
use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::sync::{Arc, Mutex};
use bincode::Options;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::pin::Pin;

use super::constants::{HEADER_SIZE, MAGIC};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum Command {
    Handshake = 0x00,
    // Client
    VerifyToken = 0x01,
    GetLogin = 0x02, // with key exchange by ECDH
    ReqJudge = 0x03,
    GetJudgeStateUpdate = 0x04,
    // Server
    ReqVerifyToken = 0xF1,
    ReqLogin = 0xF2,
    GetJudge = 0xF3,
    TestCaseUpdate = 0xF4,
    Unknown = 0xFF,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[repr(C, packed)]
pub struct PacketHeader {
    magic: u32,           // 4 bytes
    pub command: Command, // 2 bytes
    pub length: u32,      // 4 bytes
}

impl PacketHeader {
    pub fn check_magic(&self) -> bool {
        self.magic == MAGIC
    }
}

const_assert!(std::mem::size_of::<Command>() == 4);
const_assert!(std::mem::size_of::<PacketHeader>() == HEADER_SIZE);

// header || body
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PacketHeady {
    pub header: PacketHeader,
    pub body: Vec<u8>,
}

impl PacketHeady {
    pub fn checksum(&self) -> [u8; 16] {
        let encoded: Vec<u8> = bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(&self)
            .unwrap();
        let mut hasher = Md5::new();
        hasher.update(encoded);
        let tmp = hasher.finalize();
        let r: &[u8; 16] = tmp.as_ref();
        r.clone()
    }

    pub fn make_packet(command: Command, body: Vec<u8>) -> Self {
        let header = PacketHeader {
            magic: MAGIC,
            command,
            length: (body.len() as u32), // safe size_of::<usize>() >= 4
        };
        PacketHeady { header, body }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Packet {
    pub heady: PacketHeady,
    pub checksum: [u8; 16], // md5 checksum of (header || body)
}

impl Packet {
    pub async fn send(&self, stream: Arc<Mutex<TcpStream>>) -> async_std::io::Result<()> {
        let header = self.heady.header;
        let body = self.heady.body.clone();
        let checksum = self.checksum;
        stream
            .lock()
            .await
            .write_all(
                &bincode::DefaultOptions::new()
                    .with_big_endian()
                    .with_fixint_encoding()
                    .serialize(&header)
                    .unwrap(),
            )
            .await?;
        stream.lock().await.write_all(&body).await?;
        stream.lock().await.write_all(&checksum).await?;
        stream.lock().await.write_all(&['\0' as u8, '\0' as u8,'\0' as u8,'\0' as u8]).await?;
        stream.lock().await.flush().await?;
        Ok(())
    }

    pub async fn send_with_sender(&self, sender: &mut Sender<Vec<u8>>) {
        let header = self.heady.header;
        let mut body = self.heady.body.clone();
        let checksum = self.checksum;
        let mut to_send = vec![];
        to_send.append(
            &mut bincode::DefaultOptions::new()
                .with_big_endian()
                .with_fixint_encoding()
                .serialize(&header)
                .unwrap(),
        );
        to_send.append(&mut body);
        to_send.append(&mut checksum.to_vec());
        to_send.push('\0' as u8);
        to_send.push('\0' as u8);
        to_send.push('\0' as u8);
        to_send.push('\0' as u8);
        sender.try_send(to_send).ok();
    }

    pub async fn from_stream(stream: Arc<Mutex<TcpStream>>) -> async_std::io::Result<Self> {
        let mut buf: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
        stream.lock().await.read_exact(&mut buf).await?;
        debug!("{:?}", buf);
        if let Ok(header) = bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .deserialize::<PacketHeader>(&buf)
        {
            if header.check_magic() {
                let mut body: Vec<u8> = Vec::new();
                body.resize(header.length as usize, 0);
                stream.lock().await.read_exact(body.as_mut_slice()).await?;
                debug!("{:?}", body.clone());
                let mut checksum: [u8; 16] = [0; 16];
                stream.lock().await.read_exact(&mut checksum).await?;
                let packet = Packet {
                    heady: PacketHeady { header, body },
                    checksum,
                };
                if packet.verify() {
                    Ok(packet)
                } else {
                    Err(Error::new(ErrorKind::InvalidData, "Packet was invalid"))
                }
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "Packet header was invalid",
                ))
            }
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Packet header was invalid",
            ))
        }
    }

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
