use std::{
    error::Error,
    net::{Ipv4Addr, ToSocketAddrs},
};
use tokio_native_tls::native_tls::TlsConnector;
use tokio_native_tls::TlsStream;

use packet::ip;
use std::sync::Arc;
use tokio::signal::ctrl_c;
use tokio_tun::Tun;

use crate::control::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};


use log::{error, info, warn};

pub struct Client {
    user_name: String,
    password: String,
    uid: u8,
    vpn_ip: Ipv4Addr,
    udp_socket: Option<Arc<UdpSocket>>,
    aes_key: Vec<u8>,
    tun: Option<Arc<Tun>>,
    server_ip: Ipv4Addr,
    server_domain: String,
    ctl_port: u32,
    data_port: u32,
}

// private implantation
impl Client {
    async fn send_msg(
        &self,
        ctl_stm: &mut TlsStream<TcpStream>,
        msg: &ClientMsg,
    ) -> Result<ServerMsg, Box<dyn Error>> {
        let buf = serde_json::to_string(&msg).unwrap();
        // println!("Sending msg: {}", buf);
        ctl_stm.write_all(buf.as_bytes()).await?;
        ctl_stm.flush().await?;
        let mut buf = [0u8; 2048];
        let n: usize = ctl_stm.read(&mut buf).await.unwrap();
        let server_msg: ServerMsg = serde_json::from_slice(&buf[..n]).unwrap();
        // println!("Received msg: {:?}", server_msg);
        Ok(server_msg)
    }

    async fn tls_stream_creator(&self) -> Result<TlsStream<TcpStream>, Box<dyn Error>> {
        info!(
            "Connecting to server: {}:{}",
            self.server_domain, self.ctl_port
        );
        let ctl_stm =
            TcpStream::connect(format!("{}:{}", self.server_domain, self.ctl_port)).await?;
        let cx = TlsConnector::builder().build()?;
        let cx = tokio_native_tls::TlsConnector::from(cx);
        let ctl_stm = cx.connect(&self.server_domain, ctl_stm).await?;
        Ok(ctl_stm)
    }

    async fn create_udp_socket(&mut self) -> Result<(), Box<dyn Error>> {
        // port?
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        udp_socket.connect(format!("{}:{}", self.server_ip.to_string(), self.data_port)).await?;
        // assign udp socket to self.udp_socket
        self.udp_socket = Some(Arc::new(udp_socket));
        Ok(())
    }
}

impl Client {
    pub fn new(
        user_name: &String,
        passwd_hash: &String,
        server_domain: &String,
        data_port: u32,
        ctl_port: u32,
    ) -> Self {
        let server_sockaddr = (server_domain.clone(), 0 as u16)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let server_ip = match server_sockaddr.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => panic!("Server ip is not ipv4"),
        };
        Self {
            user_name: user_name.clone(),
            uid: 0,
            password: passwd_hash.clone(),
            server_domain: server_domain.clone(),
            ctl_port,
            data_port,
            udp_socket: None,
            tun: None,
            vpn_ip: Ipv4Addr::new(0, 0, 0, 0),
            server_ip: server_ip,
            aes_key: Vec::new(),
        }
    }

    pub async fn login(&mut self) -> Result<(), Box<dyn Error>> {
        let client_msg = ClientMsg {
            action: ClientAction::Login,
            username: self.user_name.clone(),
            password: self.password.clone(),
        };

        info!("User Login as: {}", self.user_name);
        let mut ctl_stm = self.tls_stream_creator().await?;
        let server_msg = self.send_msg(&mut ctl_stm, &client_msg).await?;
        match server_msg.action {
            ServerAction::Fail => {
                return Err(server_msg.message.into());
            }
            ServerAction::Success => {}
        }
        self.vpn_ip = server_msg.user_ip.parse().unwrap();
        self.uid = server_msg.uid;
        self.aes_key = server_msg.key;
        info!("User Login Success, VPN IP: {}, uid: {}", self.vpn_ip, self.uid);
        Ok(())
    }

    pub async fn register(&self) -> Result<(), Box<dyn Error>> {
        let client_msg = ClientMsg {
            action: ClientAction::RegUsr,
            username: self.user_name.clone(),
            password: self.password.clone(),
        };
        let mut ctl_stm = self.tls_stream_creator().await?;

        let server_msg = self.send_msg(&mut ctl_stm, &client_msg).await?;
        match server_msg.action {
            ServerAction::Success => {
                info!("User Register Success");
                Ok(())
            }
            ServerAction::Fail => {
                error!("{}", server_msg.message);
                Err(server_msg.message.into())
            }
        }
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        self.login().await?;
        self.create_udp_socket().await?;

        let tun: Arc<Tun> = Arc::new(
            Tun::builder()
                .name("cfmcclient")
                .tap(false)
                .packet_info(false)
                .mtu(1350)
                .up()
                .address(self.vpn_ip)
                // .destination(Ipv4Addr::new(10, 1, 0, 1))
                .broadcast(Ipv4Addr::BROADCAST)
                .netmask(Ipv4Addr::new(255, 255, 255, 0))
                .try_build()
                .unwrap(),
        );
        info!("Tun created: {:?}", tun.name());

        let _tun = tun.clone();

        // vpn to tun
        let sock = self.udp_socket.as_ref().unwrap().clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                // receive udp packet and decode as ip packet
                let n = sock.recv(&mut buf).await.unwrap();
                // println!("Recv udp packet from server: size = {}", n);
                _tun.send_all(&buf[..n]).await.unwrap();
            }
        });

        // tun to vpn
        let server_ip = self.server_ip.clone();
        let data_port = self.data_port.clone();
        let udp_socket = self.udp_socket.as_ref().unwrap().clone();
        let uid = self.uid.clone();
        let aes_key = self.aes_key.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(err) => {
                        error!("{:?}", err);
                        continue;
                    }
                };
                match ip::v4::Packet::new(&buf[..n]) {
                    Ok(packet) => {
                        // println!("Recv ipv4 packet from tun: src = {:?}, dst = {:?}", packet.source(), packet.destination());
                        let dst = packet.destination();

                        if (Ipv4Addr::new(10, 0, 0, 0)..=Ipv4Addr::new(10, 0, 0, 255))
                            .contains(&dst)
                        {
                            let mut payload = Vec::new();
                            let plaintext = &buf[..n];
                            let key = Key::<Aes256Gcm>::from_slice(&aes_key);
                            let cipher = Aes256Gcm::new(key);
                            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                            let encrypted = cipher.encrypt(&nonce, plaintext).unwrap();
                            payload.extend_from_slice(uid.to_be_bytes().as_ref());
                            payload.extend_from_slice(&dst.octets());
                            payload.extend_from_slice(nonce.as_ref());
                            payload.extend_from_slice(&encrypted);
                            udp_socket.send_to(&payload, format!("{}:{}", server_ip, data_port)).await.unwrap();
                        }
                    }
                    Err(err) => {
                        error!("{:?}", err);
                    }
                }
            }
        });
        ctrl_c().await.unwrap();
        Ok(())
    }
}
    