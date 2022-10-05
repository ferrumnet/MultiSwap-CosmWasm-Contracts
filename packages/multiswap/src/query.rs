use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Uint128;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MultiswapQueryMsg {
    Liquidity { owner: String, token: String },
    AllUserLiquidity { owner: String },
    AllLiquidity {},
    Signers {},
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct LiquidityResponse {
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Liquidity {
    pub token: String,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct AllLiquidityResponse {
    pub amounts: Vec<Liquidity>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct AllUserLiquidityResponse {
    pub owner: String,
    pub amounts: Vec<Liquidity>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct SignersResponse {
    pub signers: Vec<String>,
}
