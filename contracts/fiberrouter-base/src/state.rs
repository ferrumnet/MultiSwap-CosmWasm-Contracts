use cosmwasm_std::Addr;
use cw_storage_plus::Item;

/// Store the owner of the contract to set pool
pub const OWNER: Item<Addr> = Item::new("owner");
/// Store the contract address of fundmanager pool
pub const POOL: Item<Addr> = Item::new("pool");
