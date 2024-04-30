use crate::control::*;
use std::{error::Error, net::ToSocketAddrs};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
};
use tokio_native_tls::native_tls::TlsConnector;

pub async fn start_client(
    remote_host: &String,
    port: &u32,
    ctl_port: &u32,
) -> Result<(), Box<dyn Error>> {
    // open an virtual interface for VPN
    let ctl_endpoint = format!("{}:{}", remote_host, ctl_port);

    {
        let ctl_stm = TcpStream::connect(&ctl_endpoint).await?;

        let cx = TlsConnector::builder().build()?;
        let cx = tokio_native_tls::TlsConnector::from(cx);

        let mut ctl_stm = cx.connect(remote_host, ctl_stm).await?;

        let client_msg = ClientMsg {
            action: ClientAction::RegUsr,
            user_name: "Van".to_string(),
            user_passwd_hash: "Boy Next Door".to_string(),
        };

        let buf = serde_json::to_string(&client_msg).unwrap();

        ctl_stm.write_all(buf.as_bytes()).await?;
        ctl_stm.flush().await?;
        println!("data send: {}", buf);
    }

    let data_endpoint = format!("{}:{}", remote_host, port);
    println!("data_endpoint: {}", data_endpoint);
    let remote_addr = data_endpoint.to_socket_addrs().unwrap().next().unwrap();
    println!("remote_addr: {:?}", remote_addr);

    let sock: UdpSocket = UdpSocket::bind("0.0.0.0:0").await?;
    // sock.connect("140.113.123.156:8080".to_socket_addrs().unwrap().next().unwrap()).await?;

    sock.send_to("Hello world!".as_bytes(), remote_addr).await?;
    // sock.send("Hello world!".as_bytes()).await?;
    println!("data send: Hello world!");
    tokio::signal::ctrl_c().await?;

    // let mut config = tun::Configuration::default();
    // config
    //     .address((10, 0, 0, 1))
    //     .netmask((255, 255, 255, 0))
    //     .up();

    // #[cfg(target_os = "linux")]
    // config.platform(|config| {
    //     config.packet_information(true);
    // });
    // let mut dev = tun::create(&config).unwrap();
    // let mut buf = [0; 4096];
    Ok(())
}
