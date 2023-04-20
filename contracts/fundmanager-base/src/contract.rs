use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, to_binary, Addr, Api, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo,
    Order, Response, StdError, StdResult, Storage, Uint128,
};

use fundmanager::{
    AddFoundryAssetEvent, AddLiquidityEvent, AddSignerEvent, BridgeSwapEvent,
    BridgeWithdrawSignedEvent, Fee, FundManagerExecuteMsg, FundManagerQueryMsg, Liquidity,
    MigrateMsg, RemoveFoundryAssetEvent, RemoveLiquidityEvent, RemoveSignerEvent, SetFeeEvent,
    TransferOwnershipEvent, WithdrawSignMessage,
};

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
use crate::state::{FEE, FOUNDRY_ASSETS, LIQUIDITIES, OWNER, SIGNERS, USED_MESSAGES};
use cw_storage_plus::Bound;
use cw_utils::Event;
use regex::Regex;
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
    msg: FundManagerExecuteMsg,
) -> Result<Response, ContractError> {
    let env = ExecuteEnv { deps, env, info };
    match msg {
        FundManagerExecuteMsg::TransferOwnership { new_owner } => {
            execute_ownership_transfer(env, new_owner)
        }
        FundManagerExecuteMsg::SetFee { token, fee } => execute_set_fee(env, token, fee),
        FundManagerExecuteMsg::AddSigner { signer } => execute_add_signer(env, signer),
        FundManagerExecuteMsg::RemoveSigner { signer } => execute_remove_signer(env, signer),
        FundManagerExecuteMsg::AddFoundryAsset { token } => execute_add_foundry_asset(env, token),
        FundManagerExecuteMsg::RemoveFoundryAsset { token } => {
            execute_remove_foundry_asset(env, token)
        }
        FundManagerExecuteMsg::AddLiquidity {} => execute_add_liquidity(env),
        FundManagerExecuteMsg::RemoveLiquidity { token, amount } => {
            execute_remove_liquidity(env, token, amount)
        }
        FundManagerExecuteMsg::WithdrawSigned {
            payee,
            token,
            amount,
            salt,
            signature,
        } => execute_withdraw_signed(env, payee, token, amount, salt, signature),
        FundManagerExecuteMsg::Swap {
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
    let ExecuteEnv { deps, env: _, info } = env;
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

pub fn execute_set_fee(
    env: ExecuteEnv,
    token: String,
    fee: Uint128,
) -> Result<Response, ContractError> {
    if token.is_empty() {
        return Err(ContractError::InvalidToken {});
    }
    // fee should be lower than 90%
    if fee > Uint128::from(9000u128) {
        return Err(ContractError::InvalidFeeRange {});
    }

    let ExecuteEnv { deps, env: _, info } = env;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    FEE.save(deps.storage, token.as_str(), &fee)?;

    let event = SetFeeEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
        fee: fee,
    };
    event.add_attributes(&mut rsp);

    Ok(rsp)
}

pub fn execute_add_signer(env: ExecuteEnv, signer: String) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, env: _, info } = env;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let re = Regex::new(r"^0x[a-f0-9]{40}$").unwrap();
    if !re.is_match(signer.as_str()) {
        return Err(ContractError::NotValidLowerCaseEthAddress {});
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
    let ExecuteEnv { deps, env: _, info } = env;

    if !is_signer(deps.storage, signer.to_string()) {
        return Err(ContractError::InvalidSigner {});
    }

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
    if token.is_empty() {
        return Err(ContractError::InvalidToken {});
    }

    let ExecuteEnv { deps, env: _, info } = env;

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
    if token.is_empty() {
        return Err(ContractError::InvalidToken {});
    }

    let ExecuteEnv { deps, env: _, info } = env;

    if !is_foundry_asset(deps.storage, token.to_string()) {
        return Err(ContractError::NotFoundryAsset {});
    }

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

pub fn execute_add_liquidity(env: ExecuteEnv) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, env: _, info } = env;

    // token deposit verification
    let funds: Vec<cosmwasm_std::Coin> = info.clone().funds;
    if funds.len() != 1 {
        return Err(ContractError::InvalidDeposit {});
    }

    let Coin {
        denom: token,
        amount,
    } = funds[0].to_owned();

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
            Ok(Liquidity {
                user: info.sender.to_string(),
                token: token.to_string(),
                amount: amount,
            })
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
    if token.is_empty() {
        return Err(ContractError::InvalidToken {});
    }
    if amount == Uint128::from(0u128) {
        return Err(ContractError::InvalidAmount {});
    }

    let ExecuteEnv { deps, env: _, info } = env;

    if !is_foundry_asset(deps.storage, token.to_string()) {
        return Err(ContractError::NotFoundryAsset {});
    }

    let bank_send_msg = CosmosMsg::Bank(BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: coins(amount.u128(), &token),
    });
    let mut rsp = Response::new().add_message(bank_send_msg);

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
    if token.is_empty() {
        return Err(ContractError::InvalidToken {});
    }
    if amount == Uint128::from(0u128) {
        return Err(ContractError::InvalidAmount {});
    }

    if !is_foundry_asset(env.deps.storage, token.to_string()) {
        return Err(ContractError::NotFoundryAsset {});
    }

    env.deps.api.addr_validate(&payee)?;

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

    let ExecuteEnv { deps, env: _, info } = env;

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
    target_chain_id: String,
    target_token: String,
    target_address: String,
) -> Result<Response, ContractError> {
    if target_chain_id.is_empty() || target_token.is_empty() || target_address.is_empty() {
        return Err(ContractError::InvalidTargetInfo);
    }

    let mut rsp = Response::default();
    let ExecuteEnv { deps, env: _, info } = env;

    // token deposit verification
    let funds = info.funds;
    if funds.len() != 1 {
        return Err(ContractError::InvalidDeposit {});
    }

    let Coin {
        denom: token,
        amount,
    } = funds[0].to_owned();

    // transfer fee to owner account for distribution
    let fee: Uint128;
    match FEE.load(deps.storage, &token) {
        Ok(val) => fee = val,
        Err(_) => fee = Uint128::from(0u128),
    }

    let fee_multiplier: Uint128 = Uint128::from(10000u128);
    let fee_amount = amount * fee / fee_multiplier;

    if !fee_amount.is_zero() {
        let owner = OWNER.load(deps.storage)?;
        let bank_send_msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: owner.to_string(),
            amount: coins(fee_amount.u128(), token.to_string()),
        });
        rsp = Response::new().add_message(bank_send_msg);
    }

    let event = BridgeSwapEvent {
        from: info.sender.as_str(),
        token: token.as_str(),
        amount,
        target_chain_id: &target_chain_id,
        target_token: &target_token,
        target_address: &target_address,
        fee_amount: fee_amount,
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
        message = message_str
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
    let signature_bytes = hex::decode(signature).unwrap();
    let recovery_id = signature_bytes[64] - 27;
    let calculated_pubkey = api
        .secp256k1_recover_pubkey(&message, &signature_bytes[..64], recovery_id)
        .unwrap();
    let calculated_address = ethereum_address_raw(&calculated_pubkey).unwrap();
    format!("0x{}", hex::encode(calculated_address))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: FundManagerQueryMsg) -> StdResult<Binary> {
    match msg {
        FundManagerQueryMsg::Liquidity { owner, token } => {
            to_binary(&query_liquidity(deps, owner, token)?)
        }
        FundManagerQueryMsg::AllLiquidity { start_after, limit } => {
            to_binary(&query_all_liquidity(deps, start_after, limit)?)
        }
        FundManagerQueryMsg::Owner {} => to_binary(&query_owner(deps)?),
        FundManagerQueryMsg::Signers { start_after, limit } => {
            to_binary(&query_signers(deps, start_after, limit)?)
        }
        FundManagerQueryMsg::FoundryAssets { start_after, limit } => {
            to_binary(&query_foundry_assets(deps, start_after, limit)?)
        }
        FundManagerQueryMsg::Fee { token } => to_binary(&query_fee(deps, token)?),
    }
}

pub fn query_owner(deps: Deps) -> StdResult<String> {
    let owner = OWNER.load(deps.storage)?;
    Ok(owner.to_string())
}

pub fn query_fee(deps: Deps, token: String) -> StdResult<Fee> {
    let fee = FEE.load(deps.storage, token.as_str())?;
    Ok(Fee {
        token: token,
        amount: fee,
    })
}

pub fn query_liquidity(deps: Deps, owner: String, token: String) -> StdResult<Liquidity> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    if let Ok(Some(liquidity)) = LIQUIDITIES.may_load(deps.storage, (&token, &owner_addr)) {
        return Ok(liquidity);
    }
    Err(StdError::generic_err("liquidity does not exist"))
}

pub fn query_all_liquidity(
    deps: Deps,
    start_after: Option<(String, Addr)>,
    limit: Option<u32>,
) -> StdResult<Vec<Liquidity>> {
    read_liquidities(deps.storage, deps.api, start_after, limit)
}

pub fn query_signers(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Vec<String>> {
    Ok(read_signers(deps.storage, start_after, limit))
}

pub fn query_foundry_assets(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Vec<String>> {
    Ok(read_foundry_assets(deps.storage, start_after, limit))
}

const DEFAULT_LIMIT: u32 = 10;
pub fn read_liquidities(
    storage: &dyn Storage,
    _: &dyn Api,
    start_after: Option<(String, Addr)>,
    limit: Option<u32>,
) -> StdResult<Vec<Liquidity>> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let start = calc_range_start(start_after);
    let start_key = start.map(|s| Bound::ExclusiveRaw(s));

    LIQUIDITIES
        .range(storage, start_key, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            let (_, v) = item?;
            v.to_normal()
        })
        .collect::<StdResult<Vec<Liquidity>>>()
}

// this will set the first key after the provided key, by appending a 1 byte
fn calc_range_start(start_after: Option<(String, Addr)>) -> Option<Vec<u8>> {
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
    start_after: Option<String>,
    limit: Option<u32>,
) -> Vec<String> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let start = start_after.map(|s| Bound::ExclusiveRaw(s.into()));

    SIGNERS
        .range(storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            if let Ok((_, it)) = item {
                return it;
            }
            return "".to_string();
        })
        .collect::<Vec<String>>()
}

pub fn add_used_message(storage: &mut dyn Storage, salt: String) -> StdResult<Response> {
    USED_MESSAGES.save(storage, salt.as_str(), &salt.to_string())?;
    Ok(Response::default())
}

pub fn is_used_message(storage: &dyn Storage, salt: String) -> bool {
    if let Ok(Some(_)) = USED_MESSAGES.may_load(storage, salt.as_str()) {
        return true;
    }
    false
}

pub fn is_signer(storage: &dyn Storage, signer: String) -> bool {
    if let Ok(Some(_)) = SIGNERS.may_load(storage, signer.as_str()) {
        return true;
    }
    false
}

pub fn read_foundry_assets(
    storage: &dyn Storage,
    start_after: Option<String>,
    limit: Option<u32>,
) -> Vec<String> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT) as usize;
    let start = start_after.map(|s| Bound::ExclusiveRaw(s.into()));

    FOUNDRY_ASSETS
        .range(storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| {
            if let Ok((_, it)) = item {
                return it;
            }
            return "".to_string();
        })
        .collect::<Vec<String>>()
}

pub fn is_foundry_asset(storage: &dyn Storage, foundry_asset: String) -> bool {
    if let Ok(Some(_)) = FOUNDRY_ASSETS.may_load(storage, foundry_asset.as_str()) {
        return true;
    }
    false
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}

#[cfg(test)]
mod test {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MOCK_CONTRACT_ADDR,
    };
    use cosmwasm_std::{from_binary, BalanceResponse, BankQuery, QueryRequest, Uint128};

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

    #[test]
    fn test_initialization() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        instantiate(deps.as_mut(), env, info, msg).unwrap();

        let owner = query_owner(deps.as_ref()).unwrap();
        assert_eq!(
            "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            owner
        );
    }

    #[test]
    fn test_ownership_transfer() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        execute_ownership_transfer(
            eenv,
            "cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh".to_string(),
        )
        .unwrap();
        let owner = query_owner(deps.as_ref()).unwrap();
        assert_eq!(
            "cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh".to_string(),
            owner
        );
    }

    #[test]
    fn test_signer_add_remove() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        execute_add_signer(
            eenv,
            "0x035567da27e42258c35b313095acdea4320a7465".to_string(),
        )
        .unwrap();
        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(
            signers[0],
            "0x035567da27e42258c35b313095acdea4320a7465".to_string(),
        );
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        execute_remove_signer(
            eenv,
            "0x035567da27e42258c35b313095acdea4320a7465".to_string(),
        )
        .unwrap();
        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 0);
    }

    #[test]
    fn test_foundry_asset_add_remove() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        let res = execute_add_foundry_asset(eenv, "acudos".to_string());
        assert_eq!(res.is_err(), false);
        let signer_flag: bool = is_foundry_asset(&deps.storage, "acudos".to_string());
        assert_eq!(signer_flag, true);
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        execute_remove_foundry_asset(eenv, "acudos".to_string()).unwrap();
        let signer_flag: bool = is_foundry_asset(&deps.storage, "acudos".to_string());
        assert_eq!(signer_flag, false);
    }

    #[test]
    fn test_liquidity_add_remove() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        let res = execute_add_foundry_asset(eenv, "acudos".to_string());
        assert_eq!(res.is_err(), false);
        let signer_flag: bool = is_foundry_asset(&deps.storage, "acudos".to_string());
        assert_eq!(signer_flag, true);
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym",
                &[cosmwasm_std::Coin {
                    denom: "acudos".to_string(),
                    amount: Uint128::from(1000u128),
                }],
            ),
        };

        execute_add_liquidity(eenv).unwrap();
        let liquidity = query_liquidity(
            deps.as_ref(),
            "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            "acudos".to_string(),
        )
        .unwrap();
        assert_eq!(liquidity.token, "acudos".to_string());
        assert_eq!(liquidity.amount, Uint128::from(1000u128));

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_remove_liquidity(eenv, "acudos".to_string(), Uint128::from(500u128)).unwrap();
        let liquidity = query_liquidity(
            deps.as_ref(),
            "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            "acudos".to_string(),
        )
        .unwrap();
        assert_eq!(liquidity.token, "acudos".to_string());
        assert_eq!(liquidity.amount, Uint128::from(500u128));

        // removing liquidity more than the owned liquidity
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        let res = execute_remove_liquidity(eenv, "acudos".to_string(), Uint128::from(1500u128));
        assert!(res.is_err());

        let res = deps
            .querier
            .handle_query(&QueryRequest::Bank(BankQuery::Balance {
                address: MOCK_CONTRACT_ADDR.to_string(),
                denom: "acudos".to_string(),
            }))
            .unwrap()
            .unwrap();

        let balance: BalanceResponse = from_binary(&res).unwrap();
        assert_eq!(balance.amount.to_string(), "0acudos");
    }

    #[test]
    fn test_used_message_add() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let used_msg: bool = is_used_message(deps.as_ref().storage, "0x03".to_string());
        assert_eq!(used_msg, false);

        add_used_message(deps.as_mut().storage, "0x03".to_string()).unwrap();
        let used_msg: bool = is_used_message(deps.as_ref().storage, "0x03".to_string());
        assert_eq!(used_msg, true);
    }

    #[test]
    fn test_execute_swap() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        let res = execute_add_foundry_asset(eenv, "acudos".to_string());
        assert_eq!(res.is_err(), false);

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym",
                &[cosmwasm_std::Coin {
                    denom: "acudos".to_string(),
                    amount: Uint128::from(1000u128),
                }],
            ),
        };
        execute_swap(
            eenv,
            "137".to_string(),
            "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9".to_string(),
            "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9".to_string(),
        )
        .unwrap();

        let res = deps
            .querier
            .handle_query(&QueryRequest::Bank(BankQuery::Balance {
                address: MOCK_CONTRACT_ADDR.to_string(),
                denom: "acudos".to_string(),
            }))
            .unwrap()
            .unwrap();

        let balance: BalanceResponse = from_binary(&res).unwrap();
        assert_eq!(balance.amount.to_string(), "0acudos");

        // set fee and execute swap
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym",
                &[cosmwasm_std::Coin {
                    denom: "acudos".to_string(),
                    amount: Uint128::from(1000u128),
                }],
            ),
        };
        let res = execute_set_fee(eenv, "acudos".to_string(), Uint128::from(10u128));
        assert_eq!(res.is_err(), false);

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym",
                &[cosmwasm_std::Coin {
                    denom: "acudos".to_string(),
                    amount: Uint128::from(1000u128),
                }],
            ),
        };
        let res = execute_swap(
            eenv.into(),
            "137".to_string(),
            "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9".to_string(),
            "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9".to_string(),
        );
        assert_eq!(res.is_err(), false);
    }

    #[test]
    fn test_execute_withdraw_signed() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        execute_add_signer(
            eenv,
            "0x759e2480ce80c97913e39f8b5ef67d29b975a431".to_string(),
        )
        .unwrap();

        // try adding signer with uppercase letters
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        let res = execute_add_signer(
            eenv,
            "0x859e2480Ce80c97913e39F8b5EF67d29b975A431".to_string(),
        );
        assert!(res.is_err());

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };
        let res = execute_add_foundry_asset(eenv, "acudos".to_string());
        assert_eq!(res.is_err(), false);
        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym",
                &[cosmwasm_std::Coin {
                    denom: "acudos".to_string(),
                    amount: Uint128::from(1000u128),
                }],
            ),
        };

        execute_withdraw_signed(
            eenv,
            "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            "acudos".to_string(),
            Uint128::from(1000u128),
            "0x00".to_string(),
            "a112b6508d535f091b5de8877b34213aebca322c8a4edfbdb5002416343f30b06c387379293502b43e912350693e141ce814ef507abb007a4604f3ea73f94c691b".to_string(),
        )
        .unwrap();

        let res = deps
            .querier
            .handle_query(&QueryRequest::Bank(BankQuery::Balance {
                address: MOCK_CONTRACT_ADDR.to_string(),
                denom: "acudos".to_string(),
            }))
            .unwrap()
            .unwrap();

        let balance: BalanceResponse = from_binary(&res).unwrap();
        assert_eq!(balance.amount.to_string(), "0acudos");
    }
}