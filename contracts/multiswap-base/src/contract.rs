use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, BankMsg, CosmosMsg, DepsMut, Env, MessageInfo, Response, StdResult, Uint128,
};

use multiswap::{
    AddLiquidityEvent, BridgeSwapEvent, BridgeWithdrawSignedEvent, MultiswapExecuteMsg,
    RemoveLiquidityEvent,
};

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
use crate::state::LIQUIDITIES;
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
        (&from_addr, token.as_str()),
        |balance: Option<Uint128>| -> StdResult<_> {
            Ok(balance.unwrap_or_default().checked_add(amount)?)
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
        (&from_addr, token.as_str()),
        |balance: Option<Uint128>| -> StdResult<_> {
            Ok(balance.unwrap_or_default().checked_sub(amount)?)
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
