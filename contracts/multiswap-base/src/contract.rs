use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, to_binary, Addr, Api, BankMsg, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo,
    Order, Response, StdError, StdResult, Storage, Uint128,
};
use cw_storage_plus::Bound;

use multiswap::{
    AddLiquidityEvent, BridgeSwapEvent, BridgeWithdrawSignedEvent, Liquidity, MultiswapExecuteMsg,
    MultiswapQueryMsg, RemoveLiquidityEvent,
};

use crate::error::{self, ContractError};
use crate::msg::InstantiateMsg;
use crate::state::{LIQUIDITIES, SIGNERS};
use cw_utils::Event;
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

    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    let mut rsp = Response::default();
    LIQUIDITIES.update(
        deps.storage,
        (token.as_str(), &from_addr),
        |liquidity: Option<Liquidity>| -> StdResult<_> {
            if let Some(unwrapped) = liquidity {
                return Ok(Liquidity {
                    user: from.to_string(),
                    token: token.to_string(),
                    amount: unwrapped.amount.checked_add(amount)?,
                });
            }
            return Ok(Liquidity {
                user: from.to_string(),
                token: token.to_string(),
                amount: amount,
            });
        },
    )?;

    let event = AddLiquidityEvent {
        from: from.as_str(),
        token: token.as_str(),
        amount,
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_remove_liquidity(
    env: ExecuteEnv,
    from: String,
    token: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let from_addr = env.deps.api.addr_validate(&from)?;
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    let mut rsp = Response::default();
    LIQUIDITIES.update(
        deps.storage,
        (token.as_str(), &from_addr),
        |liquidity: Option<Liquidity>| -> StdResult<_> {
            if let Some(unwrapped) = liquidity {
                return Ok(Liquidity {
                    user: from.to_string(),
                    token: token.to_string(),
                    amount: unwrapped.amount.checked_sub(amount)?,
                });
            }
            return Err(StdError::generic_err("liquidity does not exist"));
        },
    )?;

    let event = RemoveLiquidityEvent {
        from: from.as_str(),
        token: token.as_str(),
        amount,
    };
    event.add_attributes(&mut rsp);
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
    let payee_addr = env.deps.api.addr_validate(&payee)?;

    // TODO: gets signer from params
    // signer, messageBytes, err := get_signer(ctx.ChainID(), payee, amount, salt, signature)
    // if err != nil {
    //     return types.ErrUnexpectedError(k.codespace, err)
    // }

    // TODO: ensure that the signer is registered on-chain
    // if !k.IsSigner(ctx, signer.String()) {
    //     return types.ErrInvalidSigner(k.codespace)
    // }

    // TODO: avoid using same signature and salt again
    // if k.IsUsedMessage(ctx, messageBytes) {
    //     return types.ErrAlreadyUsedWithdrawMessage(k.codespace)
    // }

    let bank_send_msg = CosmosMsg::Bank(BankMsg::Send {
        to_address: payee.to_string(),
        amount: coins(amount.u128(), &token),
    });

    let mut rsp = Response::new().add_message(bank_send_msg);
    let event = BridgeWithdrawSignedEvent {
        from: from.as_str(),
        payee: payee.as_str(),
        token: token.as_str(),
        amount,
        salt: &salt,
        signature: &signature,
    };
    event.add_attributes(&mut rsp);
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

    let event = BridgeSwapEvent {
        from: from.as_str(),
        token: token.as_str(),
        amount,
        target_chain_id: &target_chain_id,
        target_token: &target_token,
        target_address: &target_address,
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

// TODO: get_signer calculate signer from withdraw signed message parameters
// pub fn get_signer(chainId string, payee string, amount sdk.Coin,
//     salt string, signature []byte) (common.Address, []byte, error) {
//     signer := common.Address{}

//     // get sign message to be used for signature verification
//     message := &types.WithdrawSignMessage{
//         ChainId: chainId,
//         Payee:   payee,
//         Amount:  amount,
//         Salt:    salt,
//     }
//     messageBytes, err := json.Marshal(message)
//     if err != nil {
//         return signer, messageBytes, err
//     }

//     // get signer from sign message and signature
//     if len(signature) > crypto.RecoveryIDOffset {
//         signature[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
//         recovered, err := crypto.SigToPub(accounts.TextHash(messageBytes), signature)
//         if err != nil {
//             return signer, messageBytes, err
//         }
//         signer = crypto.PubkeyToAddress(*recovered)
//     }

//     return signer, messageBytes, nil
// }

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: MultiswapQueryMsg) -> StdResult<Binary> {
    match msg {
        MultiswapQueryMsg::Liquidity { owner, token } => {
            to_binary(&query_liquidity(deps, owner, token)?)
        }
        MultiswapQueryMsg::AllLiquidity {} => to_binary(&query_all_liquidity(deps)?),
        MultiswapQueryMsg::Signers {} => to_binary(&query_signers(deps)?),
    }
}

pub fn query_liquidity(deps: Deps, owner: String, token: String) -> StdResult<Liquidity> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    if let Ok(Some(liquidity)) = LIQUIDITIES.may_load(deps.storage, (&token, &owner_addr)) {
        return Ok(liquidity);
    }
    return Err(StdError::generic_err("liquidity does not exist"));
}

pub fn query_all_liquidity(deps: Deps) -> StdResult<Vec<Liquidity>> {
    // Ok(LIQUIDITIES.may_load(deps.storage)?.unwrap_or_default())
    // Err(StdError::generic_err("not implemented yet"))
    // let limit: u32 = 30;
    return read_liquidities(deps.storage, deps.api);
}

pub fn query_signers(deps: Deps) -> StdResult<Vec<String>> {
    // Ok(SIGNERS.may_load(deps.storage)?.unwrap_or_default())
    Ok(read_signers(deps.storage, deps.api))
}

const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;
pub fn read_liquidities(
    storage: &dyn Storage,
    api: &dyn Api,
    // start_after: Option<(String, String)>,
    // limit: Option<u32>,
) -> StdResult<Vec<Liquidity>> {
    let limit = DEFAULT_LIMIT as usize;
    // let start = calc_range_start(start_after);
    // let start_key = start.map(Bound::exclusive);

    LIQUIDITIES
        .range(storage, None, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            let (_, v) = item?;
            v.to_normal(api)
        })
        .collect::<StdResult<Vec<Liquidity>>>()
}

// this will set the first key after the provided key, by appending a 1 byte
fn calc_range_start(start_after: Option<(String, String)>) -> Option<Vec<u8>> {
    start_after.map(|info| {
        let mut v = [info.0.as_bytes(), info.1.as_bytes()]
            .concat()
            .as_slice()
            .to_vec();
        v.push(1);
        v
    })
}

pub fn read_signers(
    storage: &dyn Storage,
    api: &dyn Api,
    // start_after: Option<(String, String)>,
    // limit: Option<u32>,
) -> Vec<String> {
    let limit = DEFAULT_LIMIT as usize;
    // let start = calc_range_start(start_after);
    // let start_key = start.map(Bound::exclusive);

    return SIGNERS
        .range(storage, None, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            if let Ok((_, it)) = item {
                return it;
            }
            return "".to_string();
        })
        .collect::<Vec<String>>();
}
