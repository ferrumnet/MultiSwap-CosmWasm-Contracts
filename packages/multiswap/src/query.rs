use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Api, StdResult, Uint128};

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MultiswapQueryMsg {
    Liquidity {
        owner: String,
        token: String,
    },
    AllLiquidity {
        start_after: Option<(String, Addr)>,
        limit: Option<u32>,
    },
    Owner {},
    Signers {
        start_after: Option<String>,
        limit: Option<u32>,
    },
    FoundryAssets {
        start_after: Option<String>,
        limit: Option<u32>,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Liquidity {
    pub user: String,
    pub token: String,
    pub amount: Uint128,
}

impl Liquidity {
    pub fn to_normal(&self, api: &dyn Api) -> StdResult<Liquidity> {
        Ok(Liquidity {
            user: self.user.to_string(),
            token: self.token.to_string(),
            amount: self.amount,
        })
    }
}
