use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use fundmanager::Liquidity;

/// Store the owner of the contract to add/remove signers
pub const OWNER: Item<Addr> = Item::new("owner");
/// Store the fee collector address
pub const FEE_COLLECTOR: Item<Addr> = Item::new("fee_collector");
/// Store fee configuration
pub const FEE: Map<&str, Uint128> = Map::new("fee");
/// Store the liquidities map, `(owner, token) -> liquidity`
pub const LIQUIDITIES: Map<(&str, &Addr), Liquidity> = Map::new("liquidities");
/// Store signers.
pub const SIGNERS: Map<&str, String> = Map::new("signers");
/// Store messages.
pub const USED_MESSAGES: Map<&str, String> = Map::new("used_messages");
/// Store foundry assets.
pub const FOUNDRY_ASSETS: Map<&str, String> = Map::new("foundry_assets");
