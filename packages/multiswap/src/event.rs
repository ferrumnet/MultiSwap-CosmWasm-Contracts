use cosmwasm_std::{attr, Response, Uint128};
use cw_utils::Event;

/// Tracks ownership transfer
pub struct TransferOwnershipEvent<'a> {
    pub prev_owner: &'a str,
    pub new_owner: &'a str,
}

impl<'a> Event for TransferOwnershipEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "transfer_ownership"));
        rsp.attributes.push(attr("prev_owner", self.prev_owner));
        rsp.attributes.push(attr("new_owner", self.new_owner));
    }
}

/// Tracks signer additions
pub struct AddSignerEvent<'a> {
    pub from: &'a str,
    pub signer: &'a str,
}

impl<'a> Event for AddSignerEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "add_signer"));
        rsp.attributes.push(attr("signer", self.signer));
        rsp.attributes.push(attr("from", self.from));
    }
}

/// Tracks signer removals
pub struct RemoveSignerEvent<'a> {
    pub from: &'a str,
    pub signer: &'a str,
}

impl<'a> Event for RemoveSignerEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "remove_signer"));
        rsp.attributes.push(attr("signer", self.signer));
        rsp.attributes.push(attr("from", self.from));
    }
}

/// Tracks foundry asset additions
pub struct AddFoundryAssetEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
}

impl<'a> Event for AddFoundryAssetEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "add_foundry_asset"));
        rsp.attributes.push(attr("token", self.token));
        rsp.attributes.push(attr("from", self.from));
    }
}

/// Tracks foundry asset removals
pub struct RemoveFoundryAssetEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
}

impl<'a> Event for RemoveFoundryAssetEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "remove_foundry_asset"));
        rsp.attributes.push(attr("token", self.token));
        rsp.attributes.push(attr("from", self.from));
    }
}

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
