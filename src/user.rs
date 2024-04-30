
use std::sync::Arc;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::collections::HashSet;
#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub passwd_hash: String,
    pub vpn_ip: Ipv4Addr,
    pub remote_ip: SocketAddr,
    pub key: Vec<u8>,
}

impl User {
    fn reg_user(&mut self, name: String, passwd_hash: String) {
        self.name = name;
        self.passwd_hash = passwd_hash;
    }

    fn auth_user(&self, name: String, passwd_hash: String) -> bool {
        if self.name == name && self.passwd_hash == passwd_hash {
            return true;
        }
        return false;
    }
}

pub struct UserList {
    users: HashMap<Ipv4Addr, Arc<User>>,
    unused_ip: HashSet<Ipv4Addr>,
}

pub enum UserRegErr {
    UnavailableUserName,
    UnavailableUserIp,
    UnknowError,
}

impl std::fmt::Display for UserRegErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UserRegErr::UnavailableUserName => write!(f, "User name is unavailable"),
            UserRegErr::UnavailableUserIp => write!(f, "User ip is unavailable"),
            UserRegErr::UnknowError => write!(f, "Unknow error"),
        }
    }

}

impl UserList {
    pub fn new() -> UserList {
        let mut l = UserList {
            users: HashMap::new(),
            unused_ip: HashSet::new(),
        };
        for i in 2..254 {
            l.unused_ip.insert(Ipv4Addr::new(10, 0, 0, i));
        }
        l
    }

    fn pop_ip(&mut self) -> Option<Ipv4Addr> {
        if let Some(&ip) = self.unused_ip.iter().next() {
            self.unused_ip.remove(&ip);
            return Some(ip);
        }
        return None;
    }

    fn release_ip(&mut self, ip: Ipv4Addr) {
        self.unused_ip.insert(ip);
    }

    pub fn reg_user(&mut self, name: String, passwd_hash: String, remote_ip: SocketAddr) -> Result<Arc<User>, UserRegErr>{
        for user in self.users.iter() {
            if user.1.name == name {
                return Err(UserRegErr::UnavailableUserName);
            }
        }
        if let Some(ip) = self.pop_ip() {
            let user = User {
                name: name,
                passwd_hash: passwd_hash,
                vpn_ip: ip,
                remote_ip: remote_ip,
                key: Vec::new(),
            };
            let new_user = Arc::new(user);
            self.users.insert(ip, new_user.clone());
            return Ok(new_user.clone());
        }
        Err(UserRegErr::UnavailableUserIp)
    }

    pub fn get_user_by_name(&self, name: String) -> Option<&User> {
        for user in self.users.iter() {
            if user.1.name == name {
                return Some(&user.1);
            }
        }
        None
    }

    pub fn get_user_by_ip(&self, ip: Ipv4Addr) -> Option<&User> {
        if let Some(user) = self.users.get(&ip) {
            return Some(user);
        }
        None
    }
    
}
