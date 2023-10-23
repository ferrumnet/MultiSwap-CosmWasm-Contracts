use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, to_binary, Addr, Api, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo,
    Order, Response, StdError, StdResult, Storage, Uint128,
};

use fundmanager::{
    AddFoundryAssetEvent, AddLiquidityEvent, AddSignerEvent, BridgeSwapEvent,
    BridgeWithdrawSignedEvent, Fee, FundManagerExecuteMsg, FundManagerQueryMsg, Liquidity,
    MigrateMsg, RemoveFoundryAssetEvent, RemoveLiquidityEvent, RemoveSignerEvent,
    SetFeeCollectorEvent, SetFeeEvent, TransferOwnershipEvent, WithdrawSignMessage,
};

use crate::error::ContractError;
use crate::msg::InstantiateMsg;
use crate::state::{
    FEE, FEE_COLLECTOR, FOUNDRY_ASSETS, LIQUIDITIES, OWNER, SIGNERS, USED_MESSAGES,
};
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
    let fee_collector = deps.api.addr_validate(&msg.fee_collector)?;
    FEE_COLLECTOR.save(deps.storage, &fee_collector)?;
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
        FundManagerExecuteMsg::SetFeeCollector { collector } => {
            execute_set_fee_collector(env, collector)
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
            swap_bridge_amount,
        } => execute_swap(
            env,
            target_chain_id,
            target_token,
            target_address,
            swap_bridge_amount,
        ),
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

pub fn execute_set_fee_collector(
    env: ExecuteEnv,
    collector: String,
) -> Result<Response, ContractError> {
    let ExecuteEnv { deps, env: _, info } = env;
    let collector_addr = deps.api.addr_validate(&collector)?;

    if info.sender != OWNER.load(deps.storage)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut rsp = Response::default();
    FEE_COLLECTOR.save(deps.storage, &collector_addr)?;

    let event = SetFeeCollectorEvent {
        from: info.sender.as_str(),
        collector: collector.as_str(),
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
    swap_bridge_amount: Uint128,
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
        let fee_collector = FEE_COLLECTOR.load(deps.storage)?;
        let bank_send_msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: fee_collector.to_string(),
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
        swap_bridge_amount: swap_bridge_amount,
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
        FundManagerQueryMsg::FeeCollector {} => to_binary(&query_fee_collector(deps)?),
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

pub fn query_fee_collector(deps: Deps) -> StdResult<String> {
    let owner = FEE_COLLECTOR.load(deps.storage)?;
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
    use cosmwasm_std::{
        attr, from_binary, to_binary, Addr, BalanceResponse, BankQuery, QueryRequest, Response,
        Uint128,
    };

    use fundmanager::{FundManagerExecuteMsg, FundManagerQueryMsg, MigrateMsg};

    use crate::error::ContractError;
    use crate::msg::InstantiateMsg;
    use crate::state::OWNER;

    use crate::contract::{
        add_used_message, ethereum_address_raw, execute, execute_add_foundry_asset,
        execute_add_liquidity, execute_add_signer, execute_ownership_transfer,
        execute_remove_foundry_asset, execute_remove_liquidity, execute_remove_signer,
        execute_set_fee, execute_set_fee_collector, execute_swap, execute_withdraw_signed,
        get_signer, instantiate, is_foundry_asset, is_used_message, migrate, query,
        query_all_liquidity, query_fee, query_fee_collector, query_liquidity, query_owner,
        query_signers, read_foundry_assets, read_signers, ExecuteEnv,
    };

    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MOCK_CONTRACT_ADDR,
    };

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
        let owner = "address_to_be_owner";
        let deployer = "some_address";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(deployer, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        assert_eq!(query_owner(deps.as_ref()).unwrap(), owner.to_string());
        assert_eq!(OWNER.load(&deps.storage).unwrap(), owner.to_string());
        let rsp = read_signers(&deps.storage, None, None);
        assert_eq!(rsp.len(), 0);
    }

    #[test]
    fn test_ownership_transfer() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            fee_collector: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
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
            fee_collector: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
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
            fee_collector: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
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
            fee_collector: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
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

        let all_liquidity = query_all_liquidity(
            deps.as_ref(),
            Some((
                "acudos".to_string(),
                Addr::unchecked("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym"),
            )),
            Some(10u32),
        )
        .unwrap();
        assert_eq!(all_liquidity.len(), 0);

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
            fee_collector: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
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
    fn test_execute_ownership_transfer() {
        let first_owner = "address_to_be_first_owner";
        let second_owner = "address_to_be_second_owner";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(first_owner, &[]);
        let msg = InstantiateMsg {
            owner: first_owner.to_string(),
            fee_collector: first_owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_ownership_transfer(execute_env, second_owner.to_string()).unwrap();
        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "transfer_ownership".to_string()),
                attr("prev_owner", first_owner.to_string()),
                attr("new_owner", second_owner.to_string())
            ]
        );
        assert_eq!(
            query_owner(deps.as_ref()).unwrap(),
            second_owner.to_string()
        );
        assert_eq!(OWNER.load(&deps.storage).unwrap(), second_owner.to_string());
    }

    #[test]
    fn test_execute_ownership_transfer_catch_err_unauthorized() {
        let first_owner = "address_to_be_first_owner";
        let second_owner = "address_to_be_second_owner";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(first_owner, &[]);
        let msg = InstantiateMsg {
            owner: first_owner.to_string(),
            fee_collector: first_owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other_address", &[]),
        };

        assert_eq!(
            execute_ownership_transfer(execute_env, second_owner.to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_set_fee_collector() {
        let owner = "address_to_be_owner";
        let collector = "address_to_be_collector";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_set_fee_collector(execute_env, collector.to_string()).unwrap();
        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "set_fee_collector".to_string()),
                attr("collector", collector.to_string()),
                attr("from", owner.to_string())
            ]
        );

        let query_res = query_fee_collector(deps.as_ref()).unwrap();
        assert_eq!(query_res, collector.to_string());
    }

    #[test]
    fn test_execute_set_fee_collector_catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let collector = "address_to_be_collector";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_set_fee_collector(execute_env, collector.to_string(),)
                .unwrap_err()
                .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_set_fee() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_set_fee(
            execute_env,
            "token_address".to_string(),
            Uint128::from(1u128),
        )
        .unwrap();
        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "set_fee".to_string()),
                attr("fee", "1".to_string()),
                attr("token", "token_address".to_string()),
                attr("from", owner.to_string())
            ]
        );

        let query_res = query_fee(deps.as_ref(), "token_address".to_string()).unwrap();
        assert_eq!(query_res.token, "token_address".to_string());
        assert_eq!(query_res.amount, Uint128::from(1u128));
    }

    #[test]
    fn test_execute_set_fee_catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_set_fee(
                execute_env,
                "token_address".to_string(),
                Uint128::from(1u128)
            )
            .unwrap_err()
            .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_set_fee_catch_err_invalid_token_address() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_set_fee(execute_env, "".to_string(), Uint128::from(1u128))
                .unwrap_err()
                .to_string(),
            (ContractError::InvalidToken {}).to_string()
        );
    }

    #[test]
    fn test_execute_set_fee_catch_err_invalid_range_fee() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_set_fee(execute_env, "token".to_string(), Uint128::from(10000u128))
                .unwrap_err()
                .to_string(),
            (ContractError::InvalidFeeRange {}).to_string()
        );
    }

    #[test]
    fn test_execute_add_signer() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );
        assert_eq!(rsp.is_err(), false);

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        )
        .unwrap();

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 2);
        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
        );
        assert_eq!(
            signers[1],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_signer".to_string()),
                attr(
                    "signer",
                    "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
                ),
                attr("from", owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_add_signer_catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_add_signer(
                execute_env,
                "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_add_signer_catch_err_invalid_ethereum_address() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_add_signer(execute_env, "signer_vfhbfh".to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::NotValidLowerCaseEthAddress {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_signer() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 2);

        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
        );
        assert_eq!(
            signers[1],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        // remove first signer
        let rsp = execute_remove_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        )
        .unwrap();

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "remove_signer".to_string()),
                attr(
                    "signer",
                    "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
                ),
                attr("from", owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_remove_signer_catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 2);

        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
        );
        assert_eq!(
            signers[1],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_remove_signer(
                execute_env,
                "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_signer_catch_err_not_signer() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 2);

        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
        );
        assert_eq!(
            signers[1],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_remove_signer(
                execute_env,
                "0x8929cbb11fdd5798db5f638a5002235c6412f14b".to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidSigner {}).to_string()
        );
    }

    #[test]
    fn test_execute_add_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_add_foundry_asset(execute_env, "token_address_2".to_string()).unwrap();

        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address_2".to_string()),
            true
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_foundry_asset".to_string()),
                attr("token", "token_address_2".to_string()),
                attr("from", owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_add_foundry_asset_catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_add_foundry_asset(execute_env, "token_address".to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_add_foundry_asset_catch_err_invalid_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_add_foundry_asset(execute_env, "".to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::InvalidToken {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address_2".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address_2".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_remove_foundry_asset(execute_env, "token_address".to_string()).unwrap();

        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            false
        );
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address_2".to_string()),
            true
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "remove_foundry_asset".to_string()),
                attr("token", "token_address".to_string()),
                attr("from", owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_remove_foundry_asset_catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(res.is_err(), false);

        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address_2".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address_2".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_remove_foundry_asset(execute_env, "token_address".to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_foundry_asset_catch_err_invalid_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address_2".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address_2".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_remove_foundry_asset(execute_env, "".to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::InvalidToken {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_foundry_asset_catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, "token_address_2".to_string());
        assert_eq!(res.is_err(), false);
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address_2".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_remove_foundry_asset(execute_env, "other_token".to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::NotFoundryAsset {}).to_string()
        );
    }

    #[test]
    fn test_execute_add_liquidity() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);
        assert_eq!(is_foundry_asset(&deps.storage, token.clone()), true);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let rsp = execute_add_liquidity(execute_env).unwrap();

        let liquidity = query_liquidity(deps.as_ref(), owner.to_string(), token.clone()).unwrap();
        assert_eq!(liquidity.token, token);
        assert_eq!(liquidity.amount, amount);

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_liquidity".to_string()),
                attr("token", token.clone()),
                attr("amount", amount),
                attr("from", owner.to_string())
            ]
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: Uint128::from(444u128),
                }],
            ),
        };

        let rsp = execute_add_liquidity(execute_env).unwrap();

        let liquidity = query_liquidity(deps.as_ref(), owner.to_string(), token.clone()).unwrap();
        assert_eq!(liquidity.token, token);
        assert_eq!(liquidity.amount, Uint128::from(1444u128));

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_liquidity".to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(444u128)),
                attr("from", owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_add_liquidity_catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_add_liquidity(execute_env).unwrap_err().to_string(),
            (ContractError::NotFoundryAsset {}).to_string()
        );
    }

    #[test]
    fn test_execute_add_liquidity_catch_err_invalid_deposit_if_more_1_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);
        assert_eq!(is_foundry_asset(&deps.storage, token.clone()), true);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[
                    cosmwasm_std::Coin {
                        denom: token.clone(),
                        amount: amount,
                    },
                    cosmwasm_std::Coin {
                        denom: "token_address_2".to_string(),
                        amount: amount,
                    },
                ],
            ),
        };

        assert_eq!(
            execute_add_liquidity(execute_env).unwrap_err().to_string(),
            (ContractError::InvalidDeposit {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_liquidity() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let res = execute_add_liquidity(execute_env);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp =
            execute_remove_liquidity(execute_env, token.clone(), Uint128::from(220u128)).unwrap();

        let liquidity = query_liquidity(deps.as_ref(), owner.to_string(), token.clone()).unwrap();

        assert_eq!(liquidity.token, token.clone());
        assert_eq!(liquidity.amount, Uint128::from(780u128));

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "remove_liquidity".to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(220u128)),
                attr("from", owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_remove_liquidity_catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_remove_liquidity(execute_env, token.clone(), Uint128::from(220u128))
                .unwrap_err()
                .to_string(),
            (ContractError::NotFoundryAsset {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_liquidity_catch_err_liquidity_does_not_exist() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let res = execute_add_liquidity(execute_env);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info("other", &[]),
        };

        assert_eq!(
            execute_remove_liquidity(execute_env, token.clone(), Uint128::from(220u128))
                .unwrap_err()
                .to_string(),
            "Generic error: liquidity does not exist".to_string()
        );
    }

    #[test]
    fn test_execute_remove_liquidity_catch_err_invalid_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let res = execute_add_liquidity(execute_env);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_remove_liquidity(execute_env, "".to_string(), Uint128::from(220u128))
                .unwrap_err()
                .to_string(),
            (ContractError::InvalidToken {}).to_string()
        );
    }

    #[test]
    fn test_execute_remove_liquidity_catch_err_zero_amount() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let res = execute_add_liquidity(execute_env);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        assert_eq!(
            execute_remove_liquidity(execute_env, token.clone(), Uint128::from(0u128))
                .unwrap_err()
                .to_string(),
            (ContractError::InvalidAmount {}).to_string()
        );
    }

    #[test]
    fn test_execute_withdraw_signed() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let signer = get_signer(
            &deps.api,
            env.block.chain_id,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        );

        let env = mock_env();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                MOCK_CONTRACT_ADDR,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let rsp = execute_withdraw_signed(
            execute_env,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "withdraw_signed".to_string()),
                attr("from", "cosmos2contract".to_string()),
                attr("payee", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(700u128)),
                attr("signer", signer.to_string()),
                attr("salt", salt.clone()),
                attr("signature", signature.to_string())
            ]
        )
    }

    #[test]
    fn test_execute_withdraw_signed_catch_err_invalid_token_address() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let signer = get_signer(
            &deps.api,
            env.block.chain_id,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        );

        let env = mock_env();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                MOCK_CONTRACT_ADDR,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_withdraw_signed(
                execute_env,
                owner.to_string(),
                "".to_string(),
                Uint128::from(700u128),
                salt.clone(),
                signature.to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidToken {}).to_string()
        );
    }

    #[test]
    fn test_execute_withdraw_signed_catch_err_zero_amount() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let signer = get_signer(
            &deps.api,
            env.block.chain_id,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        );

        let env = mock_env();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                MOCK_CONTRACT_ADDR,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_withdraw_signed(
                execute_env,
                owner.to_string(),
                token.clone(),
                Uint128::from(0u128),
                salt.clone(),
                signature.to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidAmount {}).to_string()
        );
    }

    #[test]
    fn test_execute_withdraw_signed_catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let signer = get_signer(
            &deps.api,
            env.block.chain_id,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        );

        let env = mock_env();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                MOCK_CONTRACT_ADDR,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_withdraw_signed(
                execute_env,
                owner.to_string(),
                token.clone(),
                Uint128::from(700u128),
                salt.clone(),
                signature.to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::NotFoundryAsset {}).to_string()
        );
    }

    #[test]
    fn test_execute_withdraw_signed_catch_err_invalid_signer() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd66ea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194bba41b";

        let env = mock_env();
        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                MOCK_CONTRACT_ADDR,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_withdraw_signed(
                execute_env,
                owner.to_string(),
                token.clone(),
                Uint128::from(700u128),
                salt.clone(),
                signature.to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidSigner {}).to_string()
        );
    }

    #[test]
    fn test_execute_withdraw_signed_catch_err_used_salt() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd66ea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194bba41b";

        let signer = get_signer(
            &deps.api,
            env.block.chain_id,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        );

        let env = mock_env();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let res = add_used_message(&mut deps.storage, salt.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                MOCK_CONTRACT_ADDR,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_withdraw_signed(
                execute_env,
                owner.to_string(),
                token.clone(),
                Uint128::from(700u128),
                salt.clone(),
                signature.to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::UsedSalt {}).to_string()
        );
    }

    #[test]
    fn test_execute_swap() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(700u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        // execute swap before setting fee and ensure fee is considered as zero
        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let rsp = execute_swap(
            execute_env,
            "137".to_string(),
            "token_address_out_chain".to_string(),
            "user_address_out_chain".to_string(),
            Uint128::from(10u128),
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "swap".to_string()),
                attr("from", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", amount),
                attr("fee_amount", "0".to_string()),
                attr("swap_bridge_amount", Uint128::from(10u128)),
                attr("target_chain_id", "137".to_string()),
                attr("target_token", "token_address_out_chain".to_string()),
                attr("target_address", "user_address_out_chain".to_string()),
            ]
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_set_fee(execute_env, token.clone(), Uint128::from(2000u128));
        assert_eq!(rsp.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        let rsp = execute_swap(
            execute_env,
            "137".to_string(),
            "token_address_out_chain".to_string(),
            "user_address_out_chain".to_string(),
            Uint128::from(10u128),
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "swap".to_string()),
                attr("from", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", amount),
                attr("fee_amount", "140".to_string()),
                attr("swap_bridge_amount", Uint128::from(10u128)),
                attr("target_chain_id", "137".to_string()),
                attr("target_token", "token_address_out_chain".to_string()),
                attr("target_address", "user_address_out_chain".to_string()),
            ]
        );

        let res = deps
            .querier
            .handle_query(&QueryRequest::Bank(BankQuery::Balance {
                address: owner.to_string(),
                denom: token.clone(),
            }))
            .unwrap()
            .unwrap();

        let balance: BalanceResponse = from_binary(&res).unwrap();
        assert_eq!(balance.amount.to_string(), "0token_address");
    }
    #[test]
    fn test_execute_swap_catch_err_more_1_fund() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(777u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[
                    cosmwasm_std::Coin {
                        denom: token.clone(),
                        amount: amount,
                    },
                    cosmwasm_std::Coin {
                        denom: token.clone(),
                        amount: amount,
                    },
                ],
            ),
        };

        assert_eq!(
            execute_swap(
                execute_env,
                "137".to_string(),
                "token_address_out_chain".to_string(),
                "user_address_out_chain".to_string(),
                Uint128::from(10u128),
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidDeposit {}).to_string()
        );
    }

    #[test]
    fn test_execute_swap_catch_err_invalid_target_info() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(777u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_foundry_asset(execute_env, token.clone());
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: amount,
                }],
            ),
        };

        assert_eq!(
            execute_swap(
                execute_env,
                "137".to_string(),
                "".to_string(),
                "user_address_out_chain".to_string(),
                Uint128::from(10u128),
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidTargetInfo {}).to_string()
        );
    }

    #[test]
    fn test_execute_query_multitest() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::TransferOwnership {
                new_owner: "address_to_be_owner_2".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "transfer_ownership".to_string()),
                attr("prev_owner", owner.to_string()),
                attr("new_owner", "address_to_be_owner_2".to_string())
            ]
        );

        let owner = "address_to_be_owner_2";
        let info = mock_info(owner, &[]);

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::SetFee {
                token: "token_address".to_string(),
                fee: Uint128::from(22u128),
            },
        )
        .unwrap();
        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "set_fee".to_string()),
                attr("fee", "22".to_string()),
                attr("token", "token_address".to_string()),
                attr("from", owner.to_string())
            ]
        );

        let collector = "address_to_be_collector_2";
        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::SetFeeCollector {
                collector: collector.to_string(),
            },
        )
        .unwrap();
        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "set_fee_collector".to_string()),
                attr("collector", collector.to_string()),
                attr("from", owner.to_string())
            ]
        );

        let query_res = query_fee(deps.as_ref(), "token_address".to_string()).unwrap();
        assert_eq!(query_res.token, "token_address".to_string());
        assert_eq!(query_res.amount, Uint128::from(22u128));

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::AddSigner {
                signer: "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
            },
        )
        .unwrap();

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 2);
        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
        );
        assert_eq!(
            signers[1],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_signer".to_string()),
                attr(
                    "signer",
                    "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
                ),
                attr("from", owner.to_string())
            ]
        );

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::RemoveSigner {
                signer: "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
            },
        )
        .unwrap();

        let signers: Vec<String> = query_signers(deps.as_ref(), None, None).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(
            signers[0],
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string()
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "remove_signer".to_string()),
                attr(
                    "signer",
                    "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string()
                ),
                attr("from", owner.to_string())
            ]
        );

        let res = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::AddFoundryAsset {
                token: "token_address_mock".to_string(),
            },
        );
        assert_eq!(res.is_err(), false);

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::AddFoundryAsset {
                token: "token_address".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_foundry_asset".to_string()),
                attr("token", "token_address".to_string()),
                attr("from", owner.to_string())
            ]
        );

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::RemoveFoundryAsset {
                token: "token_address_mock".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "remove_foundry_asset".to_string()),
                attr("token", "token_address_mock".to_string()),
                attr("from", owner.to_string())
            ]
        );

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: "token_address".to_string(),
                    amount: Uint128::from(22u128),
                }],
            ),
            FundManagerExecuteMsg::AddLiquidity {},
        )
        .unwrap();

        let liquidity = query_liquidity(
            deps.as_ref(),
            owner.to_string(),
            "token_address".to_string(),
        )
        .unwrap();
        assert_eq!(liquidity.token, "token_address");
        assert_eq!(liquidity.amount, Uint128::from(22u128));

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "add_liquidity".to_string()),
                attr("token", "token_address".to_string()),
                attr("amount", Uint128::from(22u128)),
                attr("from", owner.to_string())
            ]
        );

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::RemoveLiquidity {
                token: "token_address".to_string(),
                amount: Uint128::from(10u128),
            },
        )
        .unwrap();

        let liquidity = query_liquidity(
            deps.as_ref(),
            owner.to_string(),
            "token_address".to_string(),
        )
        .unwrap();

        assert_eq!(liquidity.token, "token_address".to_string());
        assert_eq!(liquidity.amount, Uint128::from(12u128));

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "remove_liquidity".to_string()),
                attr("token", "token_address".to_string()),
                attr("amount", Uint128::from(10u128)),
                attr("from", owner.to_string())
            ]
        );

        let token = "token_address".to_string();
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let signer = get_signer(
            &deps.api,
            env.block.chain_id,
            owner.to_string(),
            token.clone(),
            Uint128::from(700u128),
            salt.clone(),
            signature.to_string(),
        );

        let env = mock_env();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_add_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::WithdrawSigned {
                payee: owner.to_string(),
                token: token.clone(),
                amount: Uint128::from(700u128),
                salt: salt.clone(),
                signature: signature.to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "withdraw_signed".to_string()),
                attr("from", owner.to_string()),
                attr("payee", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(700u128)),
                attr("signer", signer.to_string()),
                attr("salt", salt.clone()),
                attr("signature", signature.to_string())
            ]
        );

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: Uint128::from(777u128),
                }],
            ),
            FundManagerExecuteMsg::Swap {
                target_chain_id: "137".to_string(),
                target_token: "token_address_out_chain".to_string(),
                target_address: "user_address_out_chain".to_string(),
                swap_bridge_amount: Uint128::from(10u128),
            },
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "swap".to_string()),
                attr("from", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(777u128)),
                attr("fee_amount", Uint128::from(1u128)),
                attr("swap_bridge_amount", Uint128::from(10u128)),
                attr("target_chain_id", "137".to_string()),
                attr("target_token", "token_address_out_chain".to_string()),
                attr("target_address", "user_address_out_chain".to_string())
            ]
        );

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::Liquidity {
                owner: owner.to_string(),
                token: token.clone(),
            },
        )
        .unwrap();
        assert_eq!(rsp.to_string(), "eyJ1c2VyIjoiYWRkcmVzc190b19iZV9vd25lcl8yIiwidG9rZW4iOiJ0b2tlbl9hZGRyZXNzIiwiYW1vdW50IjoiMTIifQ==");

        let rsp = query(deps.as_ref(), env.clone(), FundManagerQueryMsg::Owner {}).unwrap();

        assert_eq!(
            rsp.to_string(),
            to_binary(&owner.to_string()).unwrap().to_string()
        );

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::AllLiquidity {
                start_after: None,
                limit: None,
            },
        )
        .unwrap();
        assert_eq!(rsp.to_string(), "W3sidXNlciI6ImFkZHJlc3NfdG9fYmVfb3duZXJfMiIsInRva2VuIjoidG9rZW5fYWRkcmVzcyIsImFtb3VudCI6IjEyIn1d");

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::Signers {
                start_after: None,
                limit: None,
            },
        )
        .unwrap();
        assert_eq!(rsp.to_string(), "WyIweDg5MjljYmIxMWZkZDU3OThkYjVmNjM4YTUwMDIyMzVjNjQxMmYyNmEiLCIweGFkN2Y4MWNkMTg0NGMyMzk0MzQ5ZjIyMDY4Y2VmNjUxMTkwNGUwOGUiXQ==");

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::FoundryAssets {
                start_after: None,
                limit: None,
            },
        )
        .unwrap();
        assert_eq!(rsp.to_string(), "WyJ0b2tlbl9hZGRyZXNzIl0=");

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::Fee {
                token: token.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            rsp.to_string(),
            "eyJ0b2tlbiI6InRva2VuX2FkZHJlc3MiLCJhbW91bnQiOiIyMiJ9"
        );

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::FeeCollector {},
        )
        .unwrap();
        assert_eq!(rsp.to_string(), "ImFkZHJlc3NfdG9fYmVfY29sbGVjdG9yXzIi");

        let rsp = query_liquidity(
            deps.as_ref(),
            "unexist".to_string(),
            "token_address".to_string(),
        )
        .unwrap_err();

        assert_eq!(
            rsp.to_string(),
            "Generic error: liquidity does not exist".to_string()
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_remove_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );
        assert_eq!(res.is_err(), false);

        let rsp = read_signers(&deps.storage, None, None);
        assert_eq!(rsp.len(), 1);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_remove_signer(execute_env, signer.to_string());
        assert_eq!(res.is_err(), false);

        let rsp = read_signers(&deps.storage, None, None);
        assert_eq!(rsp.len(), 0);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let res = execute_remove_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(res.is_err(), false);

        let rsp = read_foundry_assets(&deps.storage, None, None);
        assert_eq!(rsp.len(), 0);
    }
    #[test]
    fn test_migrate() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            fee_collector: owner.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let rsp = migrate(deps.as_mut(), env.clone(), MigrateMsg {}).unwrap();

        assert_eq!(rsp, Response::default());
    }

    #[test]
    fn test_ethereum_address_raw() {
        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let signer = "0x910266349a2aaca44ce909b6845e8c1ab75f475e".to_string();
        let pubkey_vec: Vec<u8> = Vec::from([
            4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211,
            123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211,
            181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127,
            95, 97, 178, 42, 20, 244, 83, 87, 235,
        ]);
        let rsp = ethereum_address_raw(&pubkey_vec).unwrap();

        let address = format!("0x{}", hex::encode(&rsp));
        assert_eq!(address, signer);
    }

    #[test]
    fn test_ethereum_address_raw_catch_err_empty_key() {
        let pubkey_vec: Vec<u8> = Vec::from([]);
        assert_eq!(
            ethereum_address_raw(&pubkey_vec).unwrap_err().to_string(),
            "Generic error: Public key must not be empty".to_string()
        );
    }

    #[test]
    fn test_ethereum_address_raw_catch_err_invalid_key() {
        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let pubkey_vec: Vec<u8> = Vec::from([
            5, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211,
            123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211,
            181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127,
            95, 97, 178, 42, 20, 244, 83, 87, 235,
        ]);

        assert_eq!(
            ethereum_address_raw(&pubkey_vec).unwrap_err().to_string(),
            "Generic error: Public key must start with 0x04".to_string()
        );
    }

    #[test]
    fn test_ethereum_address_raw_catch_err_invalid_length() {
        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let pubkey_vec: Vec<u8> = Vec::from([
            4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211,
            123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211,
            181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127,
            95, 97, 178, 42, 20, 244, 83, 87, 235, 66,
        ]);

        assert_eq!(
            ethereum_address_raw(&pubkey_vec).unwrap_err().to_string(),
            "Generic error: Public key must be 65 bytes long".to_string()
        );
    }
}
