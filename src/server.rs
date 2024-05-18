use crate::control::{ClientAction, ClientMsg, ServerAction, ServerMsg};

use aes_gcm::aes::cipher::typenum::bit::B0;
use packet::ip;

use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_native_tls::native_tls::Identity;
use tokio_native_tls::{native_tls, TlsAcceptor};
use tokio::sync::Mutex;
use tokio_tun::Tun;

use crate::user_database::{self, UserList};

use log::{error, info, warn};

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};


pub struct Server{
    port: u32,
    control_port: u32,
    tun: Arc<Tun>,
    data_sock: Arc<UdpSocket>,
    user_db: Arc<Mutex<UserList>>,
    tls_acceptor: Arc<TlsAcceptor>,
    control_channel: Arc<TcpListener>,
}

impl Server {
    pub async fn new(port: &u32, control_port: &u32, cert_path: &String) -> Result<Server, Box<dyn Error>>{
        let user_db: Arc<Mutex<UserList>> = Arc::new(Mutex::new(UserList::new()));
        info!("Tun created: cfmcvpn");
        let data_addr = format!("0.0.0.0:{}", port);
        let data_sock = Arc::new(UdpSocket::bind(&data_addr).await?);
        info!("Listening on : udp::{}", &data_addr);

        info!("listening on :{}", control_port);
        let control_channel: TcpListener =
            TcpListener::bind(format!("0.0.0.0:{}", control_port)).await?;
    
        let tls_acceptor = match tls_acceptor_creator(cert_path).await {
            Ok(acceptor) => acceptor,
            Err(e) => {
                error!("Failed to create TLS acceptor: {}", e);
                return Err(e.into());
            }
        };

        let tun = Arc::new(
            Tun::builder()
                .name("cfmcvpn")
                .tap(false)
                .packet_info(false)
                .mtu(1350)
                .up()
                .address(Ipv4Addr::new(10, 0, 0, 1))
                // .destination(Ipv4Addr::new(10, 1, 0, 1))
                .broadcast(Ipv4Addr::BROADCAST)
                .netmask(Ipv4Addr::new(255, 255, 255, 0))
                .try_build()
                .unwrap(),
        );
        Ok(Server {
            port: *port,
            control_port: *control_port,
            tun,
            data_sock,
            user_db,
            tls_acceptor: Arc::new(tls_acceptor),
            control_channel : Arc::new(control_channel),
        })
    }

    async fn tun_to_sock(&mut self) -> Result<(), Box<dyn Error>>{
        let data_sock = self.data_sock.clone();
        let user_db = self.user_db.clone();
        let tun = self.tun.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = [0u8; 2048];
                let n = match tun.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("Forward loop: tun recv error: {:?}", e);
                        continue;
                    }
                };
                // Check if the packet is ipv4
                match ip::v4::Packet::new(&buf[..n]) {
                    Ok(packet) => {
                        let vpn_dst_ip = packet.destination();
                        let mut user_db = user_db.lock().await;
                        if let Some(user) = user_db.get_user_by_ip(&vpn_dst_ip) {
                            let sent_res = data_sock.send_to(&buf[..n], user.remote_ip).await;
                            match sent_res {
                                Ok(_n) => {}
                                Err(err) => {
                                    error!("Forward loop: Send error: {:?}", err);
                                }
                            }
                        } else {
                            error!("Forward loop: user not found for dst ip: {:?}", vpn_dst_ip);
                        }
                    }
                    Err(err) => {
                        warn!("Error: {:?}", err);
                    } // not ipv4 packet
                };
            }
        });
        Ok(())
    }

    async fn sock_to_tun(&mut self) -> Result<(), Box<dyn Error>> {
        let data_sock = self.data_sock.clone();
        let user_db = self.user_db.clone();
        let tun = self.tun.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, src) = data_sock
                    .recv_from(&mut buf)
                    .await
                    .expect("failed to receive from socket");
                let uid = buf[0];
                let vpn_dst = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let mut user_db = user_db.lock().await;
                if let Some(user) = user_db.get_user_by_uid(&uid) {
                    // decrypt the packet
                    let key = Key::<Aes256Gcm>::from_slice(&user.aes_key);
                    let cipher = Aes256Gcm::new(key);
                    // let nonce = Nonce::from_slice(&buf[5..]);
                    let nonce = &buf[5..17];
                    let encrypted = &buf[17..n];
                    let decrypted = match cipher.decrypt(&Nonce::from_slice(nonce), encrypted) {
                        Ok(decrypted) => decrypted,
                        Err(err) => {
                            error!("Decrypt error: {:?}", err);
                            continue;
                        }
                    };
                    user.remote_ip = src.clone();
                    if vpn_dst == Ipv4Addr::new(10, 0, 0, 1) {
                        let sent_res = tun.send_all(&decrypted).await;
                        match sent_res {
                            Ok(()) => {
                            }
                            Err(err) => {
                                error!("Send error: {:?}", err);
                            }
                        }
                    } else {
                        if let Some(user) = user_db.get_user_by_ip(&vpn_dst) {
                            let sent_res = data_sock.send_to(&decrypted, user.remote_ip).await;
                            match sent_res {
                                Ok(_n) => {
                                }
                                Err(err) => {
                                    error!("Send error: {:?}", err);
                                }
                            }
                        } else {
                            error!("User not found for vpn_dst: {:?}", vpn_dst);
                        }
                    }
                } else {
                    error!("User not found for uid: {}", uid);
                }
            }
        });
        Ok(())
    }

    async fn user_management_loop(&mut self) -> Result<(), Box<dyn Error>> {
        let control_channel = self.control_channel.clone();
        let user_db = self.user_db.clone();    
    
        loop {
            let (socket, remote_addr) = control_channel.accept().await.expect("accept error");
            let tls_acceptor = self.tls_acceptor.clone();
            info!("Accept control connection from {}", remote_addr);
            // Accept the connection.
            // Accept the TLS connection.
            let mut tls_stream = tls_acceptor.accept(socket).await.expect("accept error");
            let _user_db = user_db.clone();
            tokio::spawn(async move {
                loop {
                    let mut buf = Vec::new();        
                    let num_bytes_read = match tls_stream.read_buf(&mut buf).await {
                        Ok(0) => {
                            info!("Connection closed");
                            break;
                        }
                        Ok(n) => n,
                        Err(err) => {
                            warn!("Read error: {:?}", err);
                            break;
                        }
                    };
    
                    let mut user_db = _user_db.lock().await;
                    let client_msg: ClientMsg = serde_json::from_slice(&buf[..num_bytes_read]).unwrap();
    
                    match client_msg.action {
                        ClientAction::RegUsr => {
                            match user_db.reg_user(
                                &client_msg.username,
                                &client_msg.password,
                                &remote_addr,
                            ) {
                                Ok(uid) => {
                                    println!("User Register Success: uid={:?}", uid);
                                    send_msg(
                                        &ServerMsg {
                                            action: ServerAction::Success,
                                            uid: uid,
                                            user_name: client_msg.username,
                                            user_ip: "".to_string(),
                                            message: "Register Success".to_string(),
                                            key: vec![],
                                        },
                                        &mut tls_stream,
                                    )
                                    .await;
                                }
                                Err(err) => {
                                    let error_msg = match err {
                                        user_database::UserRegErr::UnavailableUserIp => {
                                            "No available ip".to_string()
                                        }
                                        user_database::UserRegErr::UnavailableUserName => {
                                            "User name already exists".to_string()
                                        }
                                        user_database::UserRegErr::Error(e) => e,
                                    };
                                    error!("{}", error_msg);
                                    send_msg(
                                        &ServerMsg {
                                            action: ServerAction::Fail,
                                            uid: 0,
                                            user_name: client_msg.username,
                                            user_ip: "".to_string(),
                                            message: error_msg,
                                            key: vec![],
                                        },
                                        &mut tls_stream,
                                    )
                                    .await;
                                }
                            }
                        }
                        ClientAction::Login => {
                            if let Some(user) = user_db.get_user_by_name(&client_msg.username) {
                                let user = user.clone();
                                let argon2 = argon2::Argon2::default();
                                let parsed_hash = PasswordHash::new(&user.passwd_hash).unwrap();
                                if argon2.verify_password(client_msg.password.as_bytes(), &parsed_hash).is_ok(){
                                    info!("User Login Success: {:?}", user.name);
                                    // assign user a ip
                                    let user_ip = user_db.assign_user_ip(&client_msg.username);
                                    match user_ip {
                                        Ok(ip) => {
                                            send_msg(
                                                &ServerMsg {
                                                    action: ServerAction::Success,
                                                    uid: user.uid,
                                                    user_name: client_msg.username,
                                                    user_ip: ip.to_string(),
                                                    message: "Login Success".to_string(),
                                                    key: user.aes_key.clone(),
                                                },
                                                &mut tls_stream,
                                            )
                                            .await;
                                        }
                                        Err(err) => {
                                            info!("User Login Fail: {}", err);
                                            send_msg(
                                                &ServerMsg {
                                                    action: ServerAction::Fail,
                                                    uid: 0,
                                                    user_name: client_msg.username,
                                                    user_ip: "".to_string(),
                                                    message: "No ip".to_string(),
                                                    key: vec![],
                                                },
                                                &mut tls_stream,
                                            )
                                            .await;
                                        }
                                    }
                                } else {
                                    info!("User Login Fail: {:?} password wrong", user);
                                    send_msg(
                                        &ServerMsg {
                                            action: ServerAction::Fail,
                                            uid: 0,
                                            user_name: client_msg.username,
                                            user_ip: "".to_string(),
                                            message: "Password wrong".to_string(),
                                            key: vec![],
                                        },
                                        &mut tls_stream,
                                    )
                                    .await;
                                }
                            } else {
                                info!("User Login Fail: User {} not found", client_msg.username);
                                send_msg(
                                    &ServerMsg {
                                        action: ServerAction::Fail,
                                        uid: 0,
                                        user_name: client_msg.username,
                                        user_ip: "".to_string(),
                                        message: "User not found".to_string(),
                                        key: vec![],
                                    },
                                    &mut tls_stream,
                                )
                                .await;
                            };
                        }
                        ClientAction::Disconnect => {
                            info!("User Disconnect: {:?}", client_msg.username);
                        }
                    }
                }
            });
        }
    }

    pub async fn start_server(&mut self
    ) -> Result<(), Box<dyn Error>> {
        // forward loop
        self.tun_to_sock().await?;
        self.sock_to_tun().await?;
    
    
        // open an virtual interface for VPN
        
        // user management
        self.user_management_loop().await?;
    
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
    
}

async fn tls_acceptor_creator(cert_path: &String) -> Result<TlsAcceptor, Box<dyn Error>> {
    let mut cert_file = File::open(cert_path).await?;
    let mut cert_cnt: Vec<u8> = Vec::new();
    cert_file.read_to_end(&mut cert_cnt).await?;
    let cert = Identity::from_pkcs12(cert_cnt.as_slice(), "12345678")?;
    let tls_acceptor =
        tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build()?);
    Ok(tls_acceptor)
}

async fn send_msg(server_msg: &ServerMsg, tls_stream: &mut tokio_native_tls::TlsStream<TcpStream>) {
    let server_msg_str = serde_json::to_string(&server_msg).unwrap();
    match tls_stream.write(server_msg_str.as_bytes()).await {
        Ok(_) => {}
        Err(e) => {
            warn!("Write error: {:?}", e);
        }
    };
    match tls_stream.flush().await {
        Ok(_) => {}
        Err(e) => {
            warn!("Flush error: {:?}", e);
        }
    };
}

pub async fn start_server(
    port: &u32,
    control_port: &u32,
    cert_path: &String,
) -> Result<(), Box<dyn Error>> {
    let mut server = Server::new(port, control_port, cert_path).await?;
    server.start_server().await
}