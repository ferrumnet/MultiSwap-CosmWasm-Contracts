use cosmwasm_std::{attr, Response, Uint128};
use cw_utils::Event;

/// Tracks liquidity additions
pub struct AddLiquidityEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
}

impl<'a> Event for AddLiquidityEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "add_liquidity"));
        rsp.attributes.push(attr("token", self.token));
        rsp.attributes.push(attr("amount", self.amount));
        rsp.attributes.push(attr("from", self.from));
    }
}

/// Tracks liquidity removals
pub struct RemoveLiquidityEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
}

impl<'a> Event for RemoveLiquidityEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "remove_liquidity"));
        rsp.attributes.push(attr("token", self.token));
        rsp.attributes.push(attr("amount", self.amount));
        rsp.attributes.push(attr("from", self.from));
    }
}

/// Tracks swap events
pub struct BridgeSwapEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
    pub target_chain_id: &'a str,
    pub target_token: &'a str,
    pub target_address: &'a str,
}

impl<'a> Event for BridgeSwapEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "swap"));
        rsp.attributes.push(attr("from", self.from));
        rsp.attributes.push(attr("token", self.token));
        rsp.attributes.push(attr("amount", self.amount));
        rsp.attributes
            .push(attr("target_chain_id", self.target_chain_id));
        rsp.attributes.push(attr("target_token", self.target_token));
        rsp.attributes
            .push(attr("target_address", self.target_address));
    }
}

/// Tracks withdraw signed events
pub struct BridgeWithdrawSignedEvent<'a> {
    pub from: &'a str,
    pub payee: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
    pub salt: &'a str,
    pub signature: &'a str,
}

impl<'a> Event for BridgeWithdrawSignedEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "withdraw_signed"));
        rsp.attributes.push(attr("from", self.from));
        rsp.attributes.push(attr("payee", self.payee));
        rsp.attributes.push(attr("token", self.token));
        rsp.attributes.push(attr("amount", self.amount));
        rsp.attributes.push(attr("salt", self.salt));
        rsp.attributes.push(attr("signature", self.signature));
    }
}
