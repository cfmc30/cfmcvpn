use crate::client;
use crate::control::{ClientAction, ClientMsg, ServerAction, ServerMsg};

use nix::libc::{printf, sockaddr};
use packet::{ip, Packet};
use std::error::Error;
use std::num;
use tokio::fs::File;
use tokio::net::UdpSocket;

use tokio::net::TcpStream;

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_native_tls::native_tls::Identity;
use tokio_native_tls::{native_tls, TlsAcceptor, TlsStream};

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tun::Tun;

use crate::server_user_manager::{self, User, UserList};

use log::{error, info, warn};

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
        Ok(_) => {
            println!("Send server msg: {:?}", server_msg);
        }
        Err(err) => {
            println!("Send server msg error: {:?}", err);
        }
    };
    tls_stream.flush().await.unwrap();
}

async fn user_management_loop(
    user_db: Arc<Mutex<UserList>>,
    control_port: u32,
    cert_path: &String,
) -> Result<(), Box<dyn Error>> {
    println!("listening on :{}", control_port);
    let control_channel: TcpListener =
        TcpListener::bind(format!("0.0.0.0:{}", control_port)).await?;

    let tls_acceptor = match tls_acceptor_creator(cert_path).await {
        Ok(acceptor) => acceptor,
        Err(e) => {
            warn!("Failed to create TLS acceptor: {}", e);
            return Err(e.into());
        }
    };

    loop {
        let (socket, remote_addr) = control_channel.accept().await.expect("accept error");
        let tls_acceptor = tls_acceptor.clone();
        println!("Accept control connection from {}", remote_addr);
        // Accept the connection.
        // Accept the TLS connection.
        let mut tls_stream = tls_acceptor.accept(socket).await.expect("accept error");
        let _user_db = user_db.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = Vec::new();
                
                let num_bytes_read = match tls_stream.read_buf(&mut buf).await {
                    Ok(0) => {
                        println!("Connection closed");
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
                            &client_msg.user_name,
                            &client_msg.user_passwd_hash,
                            &remote_addr,
                        ) {
                            Ok(user) => {
                                println!("User Register Success: {:?}", user);
                                send_msg(&ServerMsg {
                                    action: ServerAction::Success,
                                    user_name: client_msg.user_name,
                                    user_ip: "".to_string(),
                                    message: "Register Success".to_string(),
                                }, &mut tls_stream).await;
                            }
                            Err(err) => {
                                let error_msg = match err {
                                    server_user_manager::UserRegErr::UnavailableUserIp => {
                                        "No available ip".to_string()
                                    }
                                    server_user_manager::UserRegErr::UnavailableUserName => {
                                        "User name already exists".to_string()
                                    }
                                    server_user_manager::UserRegErr::Error(e) => e,
                                };
                                println!("{}", error_msg);
                                send_msg(&ServerMsg {
                                    action: ServerAction::Fail,
                                    user_name: client_msg.user_name,
                                    user_ip: "".to_string(),
                                    message: error_msg,
                                }, &mut tls_stream).await;
                            }
                        }
                    }
                    ClientAction::Login => {
                        if let Some(user) = user_db.get_user_by_name(&client_msg.user_name) {
                            if user.passwd_hash == client_msg.user_passwd_hash {
                                println!("User Login Success: {:?}", user);
                                // assign user a ip
                                let user_ip = user_db.assign_user_ip(&client_msg.user_name);
                                match user_ip {
                                    Ok(ip) => {
                                        
                                        send_msg(&ServerMsg {
                                            action: ServerAction::Success,
                                            user_name: client_msg.user_name,
                                            user_ip: ip.to_string(),
                                            message: "Login Success".to_string(),
                                        }, &mut tls_stream).await;
                                    }
                                    Err(err) => {
                                        println!("User Login Fail: {}", err);
                                        send_msg(&ServerMsg {
                                            action: ServerAction::Fail,
                                            user_name: client_msg.user_name,
                                            user_ip: "".to_string(),
                                            message: "No ip".to_string(),
                                        }, &mut tls_stream).await;
                                    }
                                }
                            } else {
                                println!("User Login Fail: {:?} password wrong", user);
                                send_msg(&ServerMsg {
                                    action: ServerAction::Success,
                                    user_name: client_msg.user_name,
                                    user_ip: "".to_string(),
                                    message: "Password wrong".to_string(),
                                }, &mut tls_stream).await;
                            }
                        } else {
                            println!("User Login Fail: User {} not found", client_msg.user_name);
                            send_msg(&ServerMsg {
                                action: ServerAction::Success,
                                user_name: client_msg.user_name,
                                user_ip: "".to_string(),
                                message: "User not found".to_string(),
                            }, &mut tls_stream).await;
                        };
                    }
                    ClientAction::Disconnect => {
                        println!("User Disconnect: {:?}", client_msg.user_name);
                    }
                }
            }
        });
    }
}

pub async fn start_server(
    port: &u32,
    control_port: &u32,
    cert_path: &String,
) -> Result<(), Box<dyn Error>> {
    let user_db: Arc<Mutex<UserList>> = Arc::new(Mutex::new(UserList::new()));

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
    println!("Tun created: {:?}", tun.name());

    let data_addr = format!("0.0.0.0:{}", port);
    let data_sock = Arc::new(UdpSocket::bind(&data_addr).await?);

    println!("Listening on : udp::{}", &data_addr);
    let mut buf = [0u8; 2048];

    let _data_sock = data_sock.clone();
    let _user_db = user_db.clone();
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
                    println!("Recv ipv4 packet from tun: {:?}", packet);
                    let dst_ip = packet.destination();
                    let mut user_db = _user_db.lock().await;
                    if let Some(user) = user_db.get_user_by_ip(&dst_ip) {
                        println!("User found: {:?}", user);
                        let sent_res = _data_sock.send_to(&buf, user.remote_ip).await;
                        match sent_res {
                            Ok(n) => {
                                println!("Forward loop: Sent {} bytes to {}", n, user.remote_ip);
                            }
                            Err(err) => {
                                error!("Forward loop: Send error: {:?}", err);
                            }
                        }
                    } else {
                        error!("Forward loop: user not found for dst ip: {:?}", dst_ip);
                    }
                }
                Err(err) => {
                    error!("Error: {:?}", err);
                } // not ipv4 packet
            };
        }
    });

    let _data_sock = data_sock.clone();

    tokio::spawn(async move {
        let data_sock = _data_sock.clone();
        loop {
            let (n, src) = data_sock
                .recv_from(&mut buf)
                .await
                .expect("failed to receive from socket");
            println!("Recv {} bytes from {}", n, src);
            println!("Recv data from socket: {:?}", &buf[..n]);
            // decode data as string
        }
    });

    // open an virtual interface for VPN

    // user management
    let _control_port = control_port.clone();
    let _user_db = user_db.clone();
    let _cert_path = cert_path.clone(); // Add this line to create a `'static` copy of `cert_path`

    tokio::spawn(async move {
        user_management_loop(_user_db, _control_port, &_cert_path)
            .await
            .unwrap(); // Pass a reference to `_cert_path`
    });

    tokio::signal::ctrl_c().await?;
    Ok(())
}
