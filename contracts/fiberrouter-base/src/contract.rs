use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128,
};

use fiberrouter::{
    FiberRouterExecuteMsg, FiberRouterQueryMsg, MigrateMsg, SetPoolEvent, TransferOwnershipEvent,
};
use fundmanager::{FundManagerContract, FundManagerExecuteMsg};

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
use crate::state::{OWNER, POOL};
use cw_utils::Event;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let owner = deps.api.addr_validate(&msg.owner)?;
    OWNER.save(deps.storage, &owner)?;
    let pool = deps.api.addr_validate(&msg.pool)?;
    POOL.save(deps.storage, &pool)?;
    Ok(Response::default())
}

/// To mitigate clippy::too_many_arguments warning
pub struct ExecuteEnv<'a> {
    deps: DepsMut<'a>,
    info: MessageInfo,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _: Env,
    info: MessageInfo,
    msg: FiberRouterExecuteMsg,
) -> Result<Response, ContractError> {
    let env = ExecuteEnv { deps, info };
    match msg {
        FiberRouterExecuteMsg::TransferOwnership { new_owner } => {
            execute_ownership_transfer(env, new_owner)
        }
        FiberRouterExecuteMsg::SetPool { pool } => execute_set_pool(env, pool),
        FiberRouterExecuteMsg::WithdrawSigned {
            payee,
            token,
            amount,
            salt,
            signature,
        } => execute_withdraw_signed(env, payee, token, amount, salt, signature),
        FiberRouterExecuteMsg::Swap {
            target_chain_id,
            target_token,
            target_address,
        } => execute_swap(env, target_chain_id, target_token, target_address),
    }
}

pub fn execute_ownership_transfer(
    env: ExecuteEnv,
    new_owner: String,
) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, info } = env;
    let new_owner_addr = deps.api.addr_validate(&new_owner)?;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    OWNER.save(deps.storage, &new_owner_addr)?;

    let event = TransferOwnershipEvent {
        prev_owner: info.sender.as_str(),
        new_owner: new_owner.as_str(),
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_set_pool(env: ExecuteEnv, new_pool: String) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, info } = env;
    let new_pool_addr = deps.api.addr_validate(&new_pool)?;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    POOL.save(deps.storage, &new_pool_addr)?;

    let event = SetPoolEvent {
        from: info.sender.as_str(),
        pool: new_pool.as_str(),
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_withdraw_signed(
    env: ExecuteEnv,
    payee: String,
    token: String,
    amount: Uint128,
    salt: String,
    signature: String,
) -> Result<Response, ContractError> {
    let deps = env.deps;
    let pool = POOL.load(deps.storage)?;
    let contract_addr = deps.api.addr_validate(pool.as_str())?;
    // FundManagerContract is a function helper that provides several queries and message builder.
    let fundmanager = FundManagerContract(contract_addr);
    // Call fundmanager withdraw signed
    let msg = fundmanager.call(
        FundManagerExecuteMsg::WithdrawSigned {
            payee: payee.to_string(),
            token: token.to_string(),
            amount: amount,
            salt: salt,
            signature: signature,
        },
        vec![],
    )?;

    let res = Response::new()
        .add_message(msg)
        .add_attribute("action", "withdraw_signed")
        .add_attribute("payee", payee)
        .add_attribute("token", token)
        .add_attribute("amount", amount);
    Ok(res)
}

pub fn execute_swap(
    env: ExecuteEnv,
    target_chain_id: String,
    target_token: String,
    target_address: String,
) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, info } = env;
    let pool = POOL.load(deps.storage)?;
    let contract_addr = deps.api.addr_validate(pool.as_str())?;
    // FundManagerContract is a function helper that provides several queries and message builder.
    let fundmanager = FundManagerContract(contract_addr);
    // Call fundmanager swap
    let msg = fundmanager.call(
        FundManagerExecuteMsg::Swap {
            target_chain_id: target_chain_id.to_string(),
            target_token: target_token.to_string(),
            target_address: target_address.to_string(),
        },
        info.funds,
    )?;

    let res = Response::new()
        .add_message(msg)
        .add_attribute("action", "swap")
        .add_attribute("target_chain_id", target_chain_id)
        .add_attribute("target_token", target_token)
        .add_attribute("target_address", target_address);
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: FiberRouterQueryMsg) -> StdResult<Binary> {
    match msg {
        FiberRouterQueryMsg::Owner {} => to_binary(&query_owner(deps)?),
        FiberRouterQueryMsg::Pool {} => to_binary(&query_pool(deps)?),
    }
}

pub fn query_owner(deps: Deps) -> StdResult<String> {
    let owner = OWNER.load(deps.storage)?;
    Ok(owner.to_string())
}

pub fn query_pool(deps: Deps) -> StdResult<String> {
    let pool = POOL.load(deps.storage)?;
    Ok(pool.to_string())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}
