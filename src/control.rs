use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub enum ClientAction {
    RegUsr,
    Login,
    Disconnect,
}

/// Message format from client
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientMsg {
    pub action: ClientAction,
    pub user_name: String,
    pub user_passwd_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerAction {
    Success = 1,
    Fail = 2,
}

/// Message format from server
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerMsg {
    pub action: ServerAction,
    pub user_name: String,
    pub uid: u8,
    pub user_ip: String,
    pub message: String,
}
