
use std::borrow::Borrow;
use std::borrow::BorrowMut;
use std::sync::Arc;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::collections::HashSet;
use std::cell::RefCell;
use std::sync::Mutex;
#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub passwd_hash: String,
    pub vpn_ip: Option<Ipv4Addr>,
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
    users: HashMap<Ipv4Addr, User>,
    unused_ip: HashSet<Ipv4Addr>,
}

pub enum UserRegErr {
    UnavailableUserName,
    UnavailableUserIp,
    Error(String),
}

impl std::fmt::Display for UserRegErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UserRegErr::UnavailableUserName => write!(f, "UserRegErr: User name is unavailable"),
            UserRegErr::UnavailableUserIp => write!(f, "UserRegErr: User ip is unavailable"),
            UserRegErr::Error(e) => write!(f, "UserRegErr: {}", e),
        }
    }

}

impl UserList {
    pub fn new() -> UserList {
        let mut unused_ip = HashSet::new();
        for i in 2..254 {
            unused_ip.insert(Ipv4Addr::new(10, 0, 0, i));
        }
        UserList {
            users: HashMap::new(),
            unused_ip,
        }
    }

    fn alloc_ip(&mut self, ip: &Ipv4Addr) ->Result<(),()> {
        match self.unused_ip.remove(ip) {
            true => {
                Ok(())
            },
            false => {
                Err(())
            },
        }
    }

    fn release_ip(&mut self, ip: Ipv4Addr) {
        self.unused_ip.insert(ip);
    }

    fn peek_ip(&self) -> Option<Ipv4Addr> {
        match self.unused_ip.iter().next() {
            Some(ip) => {
                Some(*ip)
            },
            None => {
                None
            },
        }
    }

    pub fn reg_user(&mut self, name: &String, passwd_hash: &String, remote_ip: &SocketAddr) -> Result<(), UserRegErr> {
        if self.users.values().any(|user| user.name == *name) {
            return Err(UserRegErr::UnavailableUserName);
        }

        let new_user = User {
            name: name.clone(),
            passwd_hash: passwd_hash.clone(),
            vpn_ip: None,
            remote_ip: remote_ip.clone(),
            key: Vec::new(),
        };

        let remote_ipv4 = match remote_ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => return Err(UserRegErr::Error("Remote ip is not ipv4".to_string())),
        };

        self.users.insert(remote_ipv4, new_user);
        Ok(())
    }

    pub fn get_user_by_name(&mut self, name: &String) -> Option<&mut User> {
        let user = self.users.iter_mut().find(|user| {
            user.1.name == *name
        });
        match user {
            None => {
                return None;
            },
            Some(user) => {
                return Some(user.1);
            },
        }
    }

    pub fn assign_user_ip(&mut self, name: &String) -> Result<Ipv4Addr, UserRegErr> {
        let new_ip = self.peek_ip();
        let user = self.get_user_by_name(name);
        match user {
            None => {
                return Err(UserRegErr::Error("User not found".to_string()));
            },
            Some(user) => {
                match new_ip {
                    None => {
                        return Err(UserRegErr::UnavailableUserIp);
                    },
                    Some(ip) => {
                        user.vpn_ip = Some(ip);
                        self.alloc_ip(&ip);
                        return Ok(ip);
                    },
                }
            },
        }
    }

    pub fn release_user_ip(&mut self, name: &String) -> Result<(), UserRegErr> {
        unimplemented!();
        // let mut user = match self.get_user_by_name(name) {
        //     Some(user) => user,
        //     None => {
        //         return Err(UserRegErr::Error("User not found".to_string()));
        //     },
        // };
        // let ip = match user.vpn_ip {
        //     Some(ip) => ip,
        //     None => {
        //         return Err(UserRegErr::Error("User ip not found".to_string()));
        //     },
        // };
        // self.release_ip(ip);
        // user.borrow_mut().vpn_ip = None;
        // Ok(())
    }

    pub fn get_user_by_ip(&mut self, ip: &Ipv4Addr) -> Option<&mut User> {
        match self.users.get_mut(ip) {
            None => {
                None
            },
            Some(user) => {
                Some(user)
            },
        }
    }
    
}
