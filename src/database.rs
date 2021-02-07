use anyhow::Result;
use serde_derive::{Serialize, Deserialize};
use std::io::prelude::*;

type SecretKey = sodiumoxide::crypto::box_::SecretKey;
type PublicKey = sodiumoxide::crypto::box_::PublicKey;

const HEADER_IDENTITY: &str = "[GQG1-ID";
const FOOTER: &str = "]";

fn to_id(pk: &PublicKey) -> String {
    let mut id = String::new();
    id.push_str(HEADER_IDENTITY);
    id.push(':');
    id.push_str(&base64::encode(&pk));
    id.push_str(FOOTER);
    return id;
}

fn from_id(id: &String) -> Result<PublicKey> {
    let mut id: &str = &id;
    if !id.starts_with(HEADER_IDENTITY) {
        return Err(anyhow!("Invalid identifier format."));
    }
    id = &id[HEADER_IDENTITY.len()..];
    if !id.starts_with(':') {
        return Err(anyhow!("Invalid identifier format."));
    }
    id = &id[1..];
    if !id.ends_with(FOOTER) {
        return Err(anyhow!("Invalid identifier format."));
    }
    id = &id[..id.len()-1];
    let raw = base64::decode(id).map_err(
        |_| anyhow!("Invalid identifier format."))?;
    let public_key = PublicKey::from_slice(&raw).ok_or(
        anyhow!("Invalid identifier format."))?;
    Ok(public_key)
}

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub key: String,
}

impl Identity {
    pub fn get_private_key(&self) -> SecretKey {
        SecretKey::from_slice(&base64::decode(&self.key).unwrap()).unwrap()
    }
    pub fn get_public_id(&self) -> String {
        to_id(&self.get_private_key().public_key())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Friend {
    pub name: String,
    pub key: String,
}

impl<'a> Friend {
    pub fn get_public_key(&self) -> PublicKey {
        from_id(&self.key).unwrap()
    }

    pub fn get_public_id(&'a self) -> &'a str {
        &self.key
    }
}

#[derive(Serialize, Deserialize)]
struct Misc {
    pub active_identity: String,
}

#[derive(Serialize, Deserialize)]
struct DatabaseFile {
    pub misc: Misc,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity: Vec<Identity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub friend: Vec<Friend>,
}

impl DatabaseFile {
    fn new() -> Self {
        Self {
            identity: Vec::new(),
            friend: Vec::new(),
            misc: Misc { active_identity: "default".to_string() }
        }
    }
}

pub struct Database {
    file: DatabaseFile,
    dirty: bool,
}

impl<'a> Database {
    pub fn config_path() -> String {
        let mut dir = dirs::home_dir().unwrap();
        dir.push(".gqg.toml");
        dir.to_str().unwrap().to_string()
    }

    pub fn message_path_buf() -> std::path::PathBuf {
        let mut dir = dirs::home_dir().unwrap();
        dir.push(".gqg/messages/");
        std::fs::create_dir_all(dir.to_str().unwrap()).unwrap();
        dir
    }

    pub fn file_path_buf() -> std::path::PathBuf {
        let mut dir = dirs::home_dir().unwrap();
        dir.push(".gqg/files/");
        std::fs::create_dir_all(dir.to_str().unwrap()).unwrap();
        dir
    }

    pub fn load() -> Self {
        let db_file: DatabaseFile;
        match std::fs::read_to_string(Self::config_path()) {
            Ok(config_file) => {
                db_file = toml::from_str(&config_file).expect("Parsing error in the configuration file.");
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    eprintln!("First time executing, creating clean configuration file...");
                    db_file = DatabaseFile::new();
                }
                else {
                    panic!("Cannot access configuration file.");
                }
            }
        }
        let mut obj = Self {
            file: db_file,
            dirty: false,
        };
        if obj.file.identity.len() == 0 {
            eprintln!("Adding a default identity...");
            obj.add_identity("default".to_string()).unwrap();
            obj.save();
        }
        return obj;
    }

    pub fn get_active_identity(&'a self) -> &'a Identity {
        self.find_identity(&self.file.misc.active_identity).unwrap()
    }

    pub fn set_active_identity(&mut self, name: &str) -> Result<()> {
        if self.find_identity(name).is_none() {
            return Err(anyhow!("No such identity."));
        }
        self.file.misc.active_identity = name.to_string();
        self.dirty = true;
        self.save();
        Ok(())
    }

    fn validate_name(_name: &str) -> Result<()> {
        // TODO
        Ok(())
    }

    fn validate_id(id: &String) -> Result<()> {
        let _ = from_id(id)?;
        Ok(())
    }

    pub fn get_identities(&'a self) -> &'a Vec<Identity> {
        &self.file.identity
    }

    pub fn find_identity(&'a self, name: &str) -> Option<&'a Identity> {
        for id in self.get_identities() {
            if id.name == name {
                return Some(id);
            }
        }
        None
    }

    pub fn add_identity(&mut self, name: String) -> Result<()> {
        Self::validate_name(&name)?;
        if self.find_identity(&name).is_some() {
            return Err(anyhow!("Identity with that name already exists."));
        }
        let (_, key) = sodiumoxide::crypto::box_::gen_keypair();
        self.file.identity.push(Identity { name, key: base64::encode(key) });
        self.dirty = true;
        self.save();
        Ok(())
    }

    pub fn get_friends(&'a self) -> &'a Vec<Friend> {
        &self.file.friend
    }

    pub fn find_friend(&'a self, name: &str) -> Option<&'a Friend> {
        for friend in self.get_friends() {
            if friend.name == name {
                return Some(friend);
            }
        }
        None
    }

    pub fn find_friend_by_key(&'a self, key: &PublicKey) -> Option<&'a Friend> {
        for friend in self.get_friends() {
            if friend.key == to_id(&key) {
                return Some(friend);
            }
        }
        None
    }

    pub fn add_friend(&mut self, name: String, key: String) -> Result<()> {
        Self::validate_name(&name)?;
        if self.find_friend(&name).is_some() {
            return Err(anyhow!("Friend with that name already exists."));
        }
        Self::validate_id(&key)?;
        self.file.friend.push(Friend { name, key });
        self.dirty = true;
        self.save();
        Ok(())
    }

    pub fn del_friend(&mut self, name: String) -> Result<()> {
        for (n, friend) in self.get_friends().iter().enumerate() {
            if friend.name == name {
                self.file.friend.remove(n);
                self.dirty = true;
                self.save();
                return Ok(());
            }
        }
        return Err(anyhow!("Friend with that name doesn't exist."));
    }

    fn save(&mut self) {
        if self.dirty {
            // TODO: make backup, so that the config file is not accidentally wiped.
            let toml = toml::to_string(&self.file).unwrap();
            let mut f = std::fs::File::create(Database::config_path()).expect("Could not write config file.");
            f.write_all(toml.as_bytes()).expect("Could not write config file.");
            f.sync_all().expect("Could not write config file.");
        }
        self.dirty = false;
    }
}

impl std::ops::Drop for Database {
    fn drop(&mut self) {
        self.save();
    }
}
