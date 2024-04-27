use std::{error::Error, net::ToSocketAddrs};
use tokio::{io::AsyncWriteExt, net::{TcpStream, UdpSocket}};
use tokio_native_tls::native_tls::TlsConnector;
use crate::control::*;

pub async fn start_client(
    remote_host: &String,
    port: &u32,
    ctl_port: &u32,
) -> Result<(), Box<dyn Error>> {
    // open an virtual interface for VPN
    let ctl_endpoint = format!("{}:{}", remote_host, ctl_port);

    let ctl_stm = TcpStream::connect(&ctl_endpoint).await?;
    
    let cx = TlsConnector::builder().build()?;
    let cx = tokio_native_tls::TlsConnector::from(cx);

    let mut ctl_stm = cx.connect(remote_host, ctl_stm).await?;

    let client_msg = ClientMsg {
        action: ClientAction::RegUsr,
        user_name: "Van".to_string(),
        user_passwd: "Boy Next Door".to_string(),
    };

    let buf = serde_json::to_string(&client_msg).unwrap();
    
    ctl_stm.write_all(buf.as_bytes()).await?;
    println!("data send: {}", buf);

    
    // let remote_addr = format!("{}:{}", endpoint, port);
    // let mut buf = [0; 2048];
    //    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    //    sock.send_to("Hello world!".as_bytes(), remote_addr).await?;
    // let mut config = tun::Configuration::default();
    // config.address((10, 0, 0, 1))
    //        .netmask((255, 255, 255, 0))
    //        .up();

    // #[cfg(target_os = "linux")]
    // config.platform(|config| {
    // 	config.packet_information(true);
    // });
    // let mut dev = tun::create(&config).unwrap();
    // let mut buf = [0; 4096];
    Ok(())
}
