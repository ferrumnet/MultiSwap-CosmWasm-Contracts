use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, to_binary, Api, BankMsg, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Order,
    Response, StdError, StdResult, Storage, Uint128,
};

use multiswap::{
    AddFoundryAssetEvent, AddLiquidityEvent, AddSignerEvent, BridgeSwapEvent,
    BridgeWithdrawSignedEvent, Liquidity, MigrateMsg, MultiswapExecuteMsg, MultiswapQueryMsg,
    RemoveFoundryAssetEvent, RemoveLiquidityEvent, RemoveSignerEvent, TransferOwnershipEvent,
    WithdrawSignMessage,
};

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
use crate::state::{FOUNDRY_ASSETS, LIQUIDITIES, OWNER, SIGNERS, USED_MESSAGES};
use cw_utils::Event;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let owner = deps.api.addr_validate(&msg.owner)?;
    OWNER.save(deps.storage, &owner)?;
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
        MultiswapExecuteMsg::TransferOwnership { new_owner } => {
            execute_ownership_transfer(env, new_owner)
        }
        MultiswapExecuteMsg::AddSigner { signer } => execute_add_signer(env, signer),
        MultiswapExecuteMsg::RemoveSigner { signer } => execute_remove_signer(env, signer),
        MultiswapExecuteMsg::AddFoundryAsset { token } => execute_add_foundry_asset(env, token),
        MultiswapExecuteMsg::RemoveFoundryAsset { token } => {
            execute_remove_foundry_asset(env, token)
        }
        MultiswapExecuteMsg::AddLiquidity { token, amount } => {
            execute_add_liquidity(env, token, amount)
        }
        MultiswapExecuteMsg::RemoveLiquidity { token, amount } => {
            execute_remove_liquidity(env, token, amount)
        }
        MultiswapExecuteMsg::WithdrawSigned {
            payee,
            token,
            amount,
            salt,
            signature,
        } => execute_withdraw_signed(env, payee, token, amount, salt, signature),
        MultiswapExecuteMsg::Swap {
            token,
            amount,
            target_chain_id,
            target_token,
            target_address,
        } => execute_swap(
            env,
            token,
            amount,
            target_chain_id,
            target_token,
            target_address,
        ),
    }
}

pub fn execute_ownership_transfer(
    env: ExecuteEnv,
    new_owner: String,
) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, env, info } = env;
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

pub fn execute_add_signer(env: ExecuteEnv, signer: String) -> Result<Response, ContractError> {
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    SIGNERS.save(deps.storage, signer.as_str(), &signer.to_string())?;

    let event = AddSignerEvent {
        from: info.sender.as_str(),
        signer: signer.as_str(),
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_remove_signer(env: ExecuteEnv, signer: String) -> Result<Response, ContractError> {
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    SIGNERS.remove(deps.storage, signer.as_str());

    let event = RemoveSignerEvent {
        from: info.sender.as_str(),
        signer: signer.as_str(),
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_add_foundry_asset(
    env: ExecuteEnv,
    token: String,
) -> Result<Response, ContractError> {
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    FOUNDRY_ASSETS.save(deps.storage, token.as_str(), &token.to_string())?;

    let event = AddFoundryAssetEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_remove_foundry_asset(
    env: ExecuteEnv,
    token: String,
) -> Result<Response, ContractError> {
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    FOUNDRY_ASSETS.remove(deps.storage, token.as_str());

    let event = RemoveFoundryAssetEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_add_liquidity(
    env: ExecuteEnv,
    token: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    if !is_foundry_asset(deps.storage, token.to_string()) {
        return Err(ContractError::NotFoundryAsset {});
    }

    let mut rsp = Response::default();
    LIQUIDITIES.update(
        deps.storage,
        (token.as_str(), &info.sender),
        |liquidity: Option<Liquidity>| -> StdResult<_> {
            if let Some(unwrapped) = liquidity {
                return Ok(Liquidity {
                    user: info.sender.to_string(),
                    token: token.to_string(),
                    amount: unwrapped.amount.checked_add(amount)?,
                });
            }
            return Ok(Liquidity {
                user: info.sender.to_string(),
                token: token.to_string(),
                amount: amount,
            });
        },
    )?;

    let event = AddLiquidityEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
        amount,
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_remove_liquidity(
    env: ExecuteEnv,
    token: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    if !is_foundry_asset(deps.storage, token.to_string()) {
        return Err(ContractError::NotFoundryAsset {});
    }

    let mut rsp = Response::default();
    LIQUIDITIES.update(
        deps.storage,
        (token.as_str(), &info.sender),
        |liquidity: Option<Liquidity>| -> StdResult<_> {
            if let Some(unwrapped) = liquidity {
                return Ok(Liquidity {
                    user: info.sender.to_string(),
                    token: token.to_string(),
                    amount: unwrapped.amount.checked_sub(amount)?,
                });
            }
            return Err(StdError::generic_err("liquidity does not exist"));
        },
    )?;

    let event = RemoveLiquidityEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
        amount,
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
    if !is_foundry_asset(env.deps.storage, token.to_string()) {
        return Err(ContractError::NotFoundryAsset {});
    }

    let payee_addr = env.deps.api.addr_validate(&payee)?;

    // gets signer from signature recovery
    let signer = get_signer(
        env.deps.api,
        env.env.block.chain_id,
        payee.to_string(),
        token.to_string(),
        amount,
        salt.to_string(),
        signature.to_string(),
    );

    // ensure that the signer is registered on-chain
    if !is_signer(env.deps.storage, signer.to_string()) {
        return Err(ContractError::InvalidSigner {});
    }

    // avoid using same salt again
    if is_used_message(env.deps.storage, salt.to_string()) {
        return Err(ContractError::UsedSalt {});
    }
    let bank_send_msg = CosmosMsg::Bank(BankMsg::Send {
        to_address: payee.to_string(),
        amount: coins(amount.u128(), &token),
    });

    let ExecuteEnv {
        mut deps,
        env: _,
        info,
    } = env;

    // put already used message to prevent double use
    add_used_message(deps.storage, salt.to_string())?;

    let mut rsp = Response::new().add_message(bank_send_msg);
    let event = BridgeWithdrawSignedEvent {
        from: info.sender.as_str(),
        payee: payee.as_str(),
        token: token.as_str(),
        amount,
        signer: signer.as_str(),
        salt: salt.as_str(),
        signature: &signature,
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

pub fn execute_swap(
    env: ExecuteEnv,
    token: String,
    amount: Uint128,
    target_chain_id: String,
    target_token: String,
    target_address: String,
) -> Result<Response, ContractError> {
    let mut rsp = Response::default();

    let ExecuteEnv {
        mut deps,
        env,
        info,
    } = env;

    // token deposit verification
    let funds = info.funds;
    if funds.len() != 1 {
        return Err(ContractError::InvalidDeposit {});
    }
    if funds[0].denom != token {
        return Err(ContractError::InvalidDeposit {});
    }
    if funds[0].amount != amount {
        return Err(ContractError::InvalidDeposit {});
    }

    let event = BridgeSwapEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
        amount,
        target_chain_id: &target_chain_id,
        target_token: &target_token,
        target_address: &target_address,
    };
    event.add_attributes(&mut rsp);
    Ok(rsp)
}

/// Returns a raw 20 byte Ethereum address
pub fn ethereum_address_raw(pubkey: &[u8]) -> StdResult<[u8; 20]> {
    let (tag, data) = match pubkey.split_first() {
        Some(pair) => pair,
        None => return Err(StdError::generic_err("Public key must not be empty")),
    };
    if *tag != 0x04 {
        return Err(StdError::generic_err("Public key must start with 0x04"));
    }
    if data.len() != 64 {
        return Err(StdError::generic_err("Public key must be 65 bytes long"));
    }

    let hash = Keccak256::digest(data);
    Ok(hash[hash.len() - 20..].try_into().unwrap())
}

// get_signer calculate signer from withdraw signed message parameters
pub fn get_signer(
    api: &dyn Api,
    chain_id: String,
    payee: String,
    token: String,
    amount: Uint128,
    salt: String,
    signature: String,
) -> String {
    // get sign message to be used for signature verification
    let message_obj = WithdrawSignMessage {
        chain_id: chain_id,
        payee: payee,
        token: token,
        amount: amount,
        salt: salt,
    };

    // Serialize it to a JSON string.
    let message_encoding = serde_json::to_string(&message_obj);
    let mut message = "".to_string();
    if let Ok(message_str) = message_encoding {
        message = message_str.to_string()
    }

    let message = Keccak256::digest(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    );
    let signature = hex::decode(signature).unwrap();

    let recovery_id = signature[64] - 27;
    let calculated_pubkey = api
        .secp256k1_recover_pubkey(&message, &signature[..64], recovery_id)
        .unwrap();
    let calculated_address = ethereum_address_raw(&calculated_pubkey).unwrap();
    let address = format!("0x{}", hex::encode(calculated_address));
    return address;
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: MultiswapQueryMsg) -> StdResult<Binary> {
    match msg {
        MultiswapQueryMsg::Liquidity { owner, token } => {
            to_binary(&query_liquidity(deps, owner, token)?)
        }
        MultiswapQueryMsg::AllLiquidity {} => to_binary(&query_all_liquidity(deps)?),
        MultiswapQueryMsg::Owner {} => to_binary(&query_owner(deps)?),
        MultiswapQueryMsg::Signers {} => to_binary(&query_signers(deps)?),
        MultiswapQueryMsg::FoundryAssets {} => to_binary(&query_foundry_assets(deps)?),
    }
}

pub fn query_owner(deps: Deps) -> StdResult<String> {
    let owner = OWNER.load(deps.storage)?;
    return Ok(owner.to_string());
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
    Ok(read_signers(deps.storage, deps.api))
}

pub fn query_foundry_assets(deps: Deps) -> StdResult<Vec<String>> {
    Ok(read_foundry_assets(deps.storage, deps.api))
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

pub fn add_used_message(storage: &mut dyn Storage, salt: String) -> StdResult<Response> {
    USED_MESSAGES.save(storage, salt.as_str(), &salt.to_string())?;
    Ok(Response::default())
}

pub fn is_used_message(storage: &dyn Storage, salt: String) -> bool {
    if let Ok(Some(_)) = USED_MESSAGES.may_load(storage, salt.as_str()) {
        return true;
    }
    return false;
}

pub fn is_signer(storage: &dyn Storage, signer: String) -> bool {
    if let Ok(Some(_)) = SIGNERS.may_load(storage, signer.as_str()) {
        return true;
    }
    return false;
}

pub fn read_foundry_assets(
    storage: &dyn Storage,
    api: &dyn Api,
    // start_after: Option<(String, String)>,
    // limit: Option<u32>,
) -> Vec<String> {
    let limit = DEFAULT_LIMIT as usize;
    // let start = calc_range_start(start_after);
    // let start_key = start.map(Bound::exclusive);

    return FOUNDRY_ASSETS
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

pub fn is_foundry_asset(storage: &dyn Storage, foundry_asset: String) -> bool {
    if let Ok(Some(_)) = FOUNDRY_ASSETS.may_load(storage, foundry_asset.as_str()) {
        return true;
    }
    return false;
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use super::*;
    use cosmwasm_std::testing::MockApi;

    #[test]
    fn test_get_signer() {
        /////////// signature generation script ///////////
        // require("dotenv").config();
        // const { Wallet, utils, providers } = require("ethers");
        // const messageText =
        //     '{"chain_id":"chain_id","payee":"payee","token":"token","amount":"10000","salt":"salt"}';
        // let provider = new providers.JsonRpcProvider();
        // let privKey = process.env.PRIVATE_KEY;
        // const wallet = new Wallet(privKey, provider);
        // const signature = await wallet.signMessage(messageText);
        // console.log("signature", signature);
        // console.log("address", wallet.address);

        let api = MockApi::default();
        let signer = get_signer(
            &api,
            "chain_id".to_string(),
            "payee".to_string(),
            "token".to_string(),
            Uint128::new(10000),
            "salt".to_string(),
            "a112b6508d535f091b5de8877b34213aebca322c8a4edfbdb5002416343f30b06c387379293502b43e912350693e141ce814ef507abb007a4604f3ea73f94c691b".to_string(),
        );

        assert_eq!(
            "0x035567da27e42258c35b313095acdea4320a7465".to_string(),
            signer
        );
    }
}
