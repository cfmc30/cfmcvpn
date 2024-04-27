use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub enum ClientAction {
    RegUsr = 1,
    Login = 2,
    Disconnect = 3,
}

/// Message format from client
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientMsg {
    pub action: ClientAction,
    pub user_name: String,
    pub user_passwd: String,
}

