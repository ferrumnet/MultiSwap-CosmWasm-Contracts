use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Uint128;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MultiswapQueryMsg {
    Liquidity { owner: String },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct LiquidityResponse {
    pub amount: Uint128,
}
