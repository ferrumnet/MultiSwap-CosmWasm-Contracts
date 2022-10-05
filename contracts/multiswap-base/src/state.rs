use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};

/// Store the owner of the contract to add/remove signers
pub const OWNER: Item<Addr> = Item::new("owner");
/// Store the liquidities map, `(owner, token) -> liquidity`
pub const LIQUIDITIES: Map<(&Addr, &str), Uint128> = Map::new("liquidities");
/// Store signers.
pub const SIGNERS: Map<&str, String> = Map::new("signers");
