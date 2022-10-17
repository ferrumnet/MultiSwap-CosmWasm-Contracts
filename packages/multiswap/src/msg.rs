use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, Uint128};

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MultiswapExecuteMsg {
    AddSigner {
        from: String,
        signer: String,
    },
    RemoveSigner {
        from: String,
        signer: String,
    },
    AddLiquidity {
        from: String,
        token: String,
        amount: Uint128,
    },
    RemoveLiquidity {
        from: String,
        token: String,
        amount: Uint128,
    },
    WithdrawSigned {
        from: String,
        payee: String,
        salt: String,
        token: String,
        amount: Uint128,
        signature: String,
    },
    Swap {
        from: String,
        token: String,
        amount: Uint128,
        target_chain_id: String,
        target_token: String,
        target_address: String,
    },
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct MigrateMsg {}
