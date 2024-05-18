use crate::user_manager::Client;
use std::error::Error;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;

pub async fn get_user_info() -> Result<(String, String), Box<dyn Error>> {
    let my_buf_read = tokio::io::BufReader::new(tokio::io::stdin());
    let mut lines = my_buf_read.lines();

    let mut stdout = tokio::io::stdout();
    stdout.write_all(b"Login: ").await?;
    stdout.flush().await?;
    let user_name = loop {
        match lines.next_line().await {
            Ok(Some(name)) => break name,
            Ok(None) => {
                continue;
            }
            Err(_e) => {
                continue;
            }
        }
    };
    // get password
    stdout.write_all(b"Password: ").await?;
    stdout.flush().await?;
    let passwd = match lines.next_line().await {
        Ok(Some(passwd)) => passwd,
        Ok(None) => {
            return Err("No password provided".into());
        }
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok((user_name, passwd))
}

pub async fn register_user(
    remote_host: &String,
    data_port: &u32,
    ctl_port: &u32,
) -> Result<(), Box<dyn Error>> {
    // get user name
    let (user_name, passwd) = get_user_info().await?;
    let client = Client::new(&user_name, &passwd, remote_host, *data_port, *ctl_port);
    client.register().await?;
    Ok(())
}

pub async fn start_client(
    remote_host: &String,
    data_port: &u32,
    ctl_port: &u32,
) -> Result<(), Box<dyn Error>> {
    // open an virtual interface for VPN
    // input user name and password
    // send register request to server

    // get user name
    let (user_name, passwd) = get_user_info().await?;
    let mut client = Client::new(&user_name, &passwd, remote_host, *data_port, *ctl_port);
    client.start().await?;
    Ok(())
}
