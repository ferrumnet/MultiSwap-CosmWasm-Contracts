use std::env::current_dir;
use std::fs::create_dir_all;

use cosmwasm_schema::{export_schema, remove_schemas, schema_for};

use multiswap::{MultiswapExecuteMsg, MultiswapQueryMsg};
use multiswap_base::msg::InstantiateMsg;

fn main() {
    let mut out_dir = current_dir().unwrap();
    out_dir.push("schema");
    create_dir_all(&out_dir).unwrap();
    remove_schemas(&out_dir).unwrap();

    export_schema(&schema_for!(InstantiateMsg), &out_dir);
    export_schema(&schema_for!(MultiswapExecuteMsg), &out_dir);
    export_schema(&schema_for!(MultiswapQueryMsg), &out_dir);
}
