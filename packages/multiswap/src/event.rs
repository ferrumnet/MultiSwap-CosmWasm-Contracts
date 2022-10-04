use cosmwasm_std::{attr, Response, Uint128};

/// Tracks token transfer/mint/burn actions
pub struct TransferEvent<'a> {
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub token_id: &'a str,
    pub amount: Uint128,
}

/// Tracks token metadata changes
pub struct MetadataEvent<'a> {
    pub url: &'a str,
    pub token_id: &'a str,
}

/// Tracks approve_all status changes
pub struct ApproveAllEvent<'a> {
    pub sender: &'a str,
    pub operator: &'a str,
    pub approved: bool,
}
