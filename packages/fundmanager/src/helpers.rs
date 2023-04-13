use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{to_binary, Addr, Coin, CosmosMsg, StdResult, WasmMsg};

use crate::FundManagerExecuteMsg;

/// FundManagerContract is a wrapper around Addr that provides a lot of helpers
/// for working with this contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct FundManagerContract(pub Addr);

impl FundManagerContract {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    pub fn call<T: Into<FundManagerExecuteMsg>>(
        &self,
        msg: T,
        funds: Vec<Coin>,
    ) -> StdResult<CosmosMsg> {
        let msg = to_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: funds,
        }
        .into())
    }
}
