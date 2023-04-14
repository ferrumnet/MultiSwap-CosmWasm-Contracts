use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Uint128;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FiberRouterExecuteMsg {
    TransferOwnership {
        new_owner: String,
    },
    SetPool {
        pool: String,
    },
    Swap {
        target_chain_id: String,
        target_token: String,
        target_address: String,
    },
    WithdrawSigned {
        payee: String,
        salt: String,
        token: String,
        amount: Uint128,
        signature: String,
    },
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct MigrateMsg {}
