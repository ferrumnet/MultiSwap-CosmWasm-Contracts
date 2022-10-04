use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, Uint128};

use multiswap::MultiswapExecuteMsg;

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
// use crate::state::{APPROVES, BALANCES, MINTER, TOKENS};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:multiswap-base";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let minter = deps.api.addr_validate(&msg.owner)?;
    // MINTER.save(deps.storage, &minter)?;
    Ok(Response::default())
}

/// To mitigate clippy::too_many_arguments warning
pub struct ExecuteEnv<'a> {
    deps: DepsMut<'a>,
    env: Env,
    info: MessageInfo,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: MultiswapExecuteMsg,
) -> Result<Response, ContractError> {
    let env = ExecuteEnv { deps, env, info };
    match msg {
        MultiswapExecuteMsg::AddLiquidity {
            from,
            token,
            amount,
        } => execute_add_liquidity(env, from, token, amount),
        MultiswapExecuteMsg::RemoveLiquidity {
            from,
            token,
            amount,
        } => execute_remove_liquidity(env, from, token, amount),
        MultiswapExecuteMsg::WithdrawSigned {
            from,
            payee,
            token,
            amount,
            salt,
            signature,
        } => execute_withdraw_signed(env, from, payee, token, amount, salt, signature),
        MultiswapExecuteMsg::Swap {
            from,
            token,
            amount,
            target_chain_id,
            target_token,
            target_address,
        } => execute_swap(
            env,
            from,
            token,
            amount,
            target_chain_id,
            target_token,
            target_address,
        ),
    }
}

pub fn execute_add_liquidity(
    env: ExecuteEnv,
    from: String,
    token: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let from_addr = env.deps.api.addr_validate(&from)?;
    let mut rsp = Response::default();
    Ok(rsp)
}

pub fn execute_remove_liquidity(
    env: ExecuteEnv,
    from: String,
    token: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let from_addr = env.deps.api.addr_validate(&from)?;
    let mut rsp = Response::default();
    Ok(rsp)
}

pub fn execute_withdraw_signed(
    env: ExecuteEnv,
    from: String,
    payee: String,
    token: String,
    amount: Uint128,
    salt: String,
    signature: String,
) -> Result<Response, ContractError> {
    let from_addr = env.deps.api.addr_validate(&from)?;
    let mut rsp = Response::default();
    Ok(rsp)
}

pub fn execute_swap(
    env: ExecuteEnv,
    from: String,
    token: String,
    amount: Uint128,
    target_chain_id: String,
    target_token: String,
    target_address: String,
) -> Result<Response, ContractError> {
    let from_addr = env.deps.api.addr_validate(&from)?;
    let mut rsp = Response::default();
    Ok(rsp)
}
