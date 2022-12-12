use cosmwasm_std::{attr, Response};
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

/// Tracks pool set event
pub struct SetPoolEvent<'a> {
    pub from: &'a str,
    pub pool: &'a str,
}

impl<'a> Event for SetPoolEvent<'a> {
    fn add_attributes(&self, rsp: &mut Response) {
        rsp.attributes.push(attr("action", "set_pool"));
        rsp.attributes.push(attr("pool", self.pool));
        rsp.attributes.push(attr("from", self.from));
    }
}
