use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use multiswap::Liquidity;

/// Store the owner of the contract to add/remove signers
pub const OWNER: Item<Addr> = Item::new("owner");
/// Store the liquidities map, `(owner, token) -> liquidity`
pub const LIQUIDITIES: Map<(&str, &Addr), Liquidity> = Map::new("liquidities");
/// Store signers.
pub const SIGNERS: Map<&str, String> = Map::new("signers");
