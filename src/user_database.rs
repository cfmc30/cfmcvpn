use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::collections::HashSet;

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


#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub uid: u8,
    pub passwd_hash: String,
    pub vpn_ip: Option<Ipv4Addr>,
    pub remote_ip: SocketAddr,
    pub aes_key: Vec<u8>,
    // pub sault: Vec<u8>,
}

// impl User {
//     fn reg_user(&mut self, name: String, passwd_hash: String) {
//         self.name = name;
//         self.passwd_hash = passwd_hash;
//     }

//     fn auth_user(&self, name: String, passwd_hash: String) -> bool {
//         if self.name == name && self.passwd_hash == passwd_hash {
//             return true;
//         }
//         return false;
//     }
// }

pub struct UserList {
    users: HashMap<u8, User>,
    unused_ip: HashSet<Ipv4Addr>,
    unused_uid: HashSet<u8>,
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
        let mut unused_uid = HashSet::new();
        for i in 2..254 {
            unused_ip.insert(Ipv4Addr::new(10, 0, 0, i));
            unused_uid.insert(i);
        }
        UserList {
            users: HashMap::new(),
            unused_ip,
            unused_uid,
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

    // fn release_ip(&mut self, ip: Ipv4Addr) {
    //     self.unused_ip.insert(ip);
    // }

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

    pub fn reg_user(&mut self, name: &String, passwd_hash: &String, remote_ip: &SocketAddr) -> Result<u8, UserRegErr> {
        if self.users.values().any(|user| user.name == *name) {
            return Err(UserRegErr::UnavailableUserName);
        }
        
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(passwd_hash.as_bytes(), &salt).unwrap().to_string();
        
        let aes_key = Aes256Gcm::generate_key(OsRng);
        let new_user = User {
            name: name.clone(),
            uid: self.unused_uid.iter().next().unwrap().clone(),
            passwd_hash: hash,
            vpn_ip: None,
            remote_ip: remote_ip.clone(),
            aes_key: aes_key.to_vec(),
        };
        self.unused_uid.remove(&new_user.uid);

        let uid = new_user.uid.clone();
        self.users.insert(new_user.uid.clone(), new_user);
        Ok(uid)
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

    pub fn get_user_by_ip(&mut self, ip: &Ipv4Addr) -> Option<&mut User> {
        let user = self.users.iter_mut().find(|user| {
            match user.1.vpn_ip {
                Some(vpn_ip) => {
                    vpn_ip == *ip
                },
                None => {
                    false
                },
            }
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
                        match self.alloc_ip(&ip) {
                            Ok(_) => {},
                            Err(_) => {
                                return Err(UserRegErr::UnavailableUserIp);
                            },
                        
                        };
                        return Ok(ip);
                    },
                }
            },
        }
    }

    pub fn get_user_by_uid(&mut self, uid: &u8) -> Option<&mut User> {
        match self.users.get_mut(uid) {
            None => {
                None
            },
            Some(user) => {
                Some(user)
            },
        }
    }
    
}
