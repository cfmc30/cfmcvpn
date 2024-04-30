use crate::control::{ClientAction, ClientMsg, ServerAction, ServerMsg};

use nix::libc::sockaddr;
use packet::{ip, Packet};
use std::error::Error;
use tokio::fs::File;
use tokio::net::UdpSocket;

use std::net::Ipv4Addr;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_native_tls::native_tls::Identity;
use tokio_native_tls::{native_tls, TlsAcceptor};

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tun::Tun;

use crate::user::{User, UserList};

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

    let data_addr = format!("0.0.0.0:{}", port);
    let data_sock = Arc::new(UdpSocket::bind(&data_addr).await?);
    println!("Listening on : udp::{}", &data_addr);
    let mut buf = [0u8; 2048];


    let _data_sock = data_sock.clone();
    let _user_db = user_db.clone();
    tokio::spawn(async move {
        loop {
            let mut buf = [0u8; 2048];
            let n = tun.recv(&mut buf).await.expect("failed to read from tun");
            println!("Recv {} bytes from tun", n);
            let ip_packet = ip::Packet::new(&buf[..n]).unwrap();
            println!("Recv data from tun: {:?}", ip_packet);
            match ip::v4::Packet::new(&buf[..n]) {
                Ok(packet) => {
                    println!("Recv ipv4 packet: {:?}", packet);
                    let dst_ip = packet.destination();
                    let user_db = _user_db.lock().await;
                    if let Some(user) = user_db.get_user_by_ip(dst_ip) {
                        println!("User found: {:?}", user);
                        _data_sock.send_to(&buf, user.remote_ip).await;
                    } else {
                        println!("User not found");
                    }
                }
                Err(err) => {}
            };
            // if packet is ipv4
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
        }
    });

    // open an virtual interface for VPN

    let control_channel: TcpListener =
        TcpListener::bind(format!("0.0.0.0:{}", control_port)).await?;

    // open cert_path
    let mut cert_file = File::open(cert_path).await?;
    let mut cert_cnt: Vec<u8> = Vec::new();
    cert_file.read_to_end(&mut cert_cnt).await?;

    let cert = Identity::from_pkcs12(cert_cnt.as_slice(), "12345678")?;
    let tls_acceptor =
        tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build()?);
    let _data_sock = data_sock.clone();
    let _user_db = user_db.clone();
    tokio::spawn(async move {
        loop {
            let (socket, remote_addr) = control_channel.accept().await.expect("accept error");
            let tls_acceptor = tls_acceptor.clone();
            println!("Accept control connection from {}", remote_addr);
            // Accept the connection.
            // Accept the TLS connection.
            let mut tls_stream = tls_acceptor.accept(socket).await.expect("accept error");
            let user_db = _user_db.clone();
            tokio::spawn(async move {
                loop {
                    let mut buf = Vec::new();
                    let n = tls_stream
                        .read_to_end(&mut buf)
                        .await
                        .expect("failed to read data from socket");

                    if n == 0 {
                        // connection closed
                        println!("Connection closed");
                        break;
                    }
                    let mut user_db = user_db.lock().await;

                    let client_msg: ClientMsg = serde_json::from_slice(buf.as_slice()).unwrap();
                    match client_msg.action {
                        ClientAction::RegUsr => {
                            match user_db.reg_user(
                                client_msg.user_name,
                                client_msg.user_passwd_hash,
                                remote_addr,
                            ) {
                                Ok(user) => {
                                    println!("User Register Success: {:?}", user);
                                }
                                Err(err) => {
                                    println!("User Register Fail: {}", err);
                                }
                            }
                        }
                        ClientAction::Login => {
                            println!("User Login: {:?}", client_msg);
                        }
                        ClientAction::Disconnect => {
                            println!("User Disconnect: {:?}", client_msg);
                        }
                    }
                }
            });
        }
    });

    tokio::signal::ctrl_c().await?;
    Ok(())
}
