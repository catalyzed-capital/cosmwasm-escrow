use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use cw_utils::Expiration;

#[cw_serde]
//this is storing contract data 
pub struct Config {
    pub arbiter: Addr, //addresses stored here 
    pub recipient: Addr,
    pub source: Addr,
    pub expiration: Option<Expiration>,
}

pub const CONFIG_KEY: &str = "config";
pub const CONFIG: Item<Config> = Item::new(CONFIG_KEY); //Item stores (one type Item) at the given key

//we create a constant for steal
pub const THIEF: &str = "changeme";
