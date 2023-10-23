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
    swap_bridge_amount: Uint128,
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
            swap_bridge_amount: swap_bridge_amount,
        },
        info.funds,
    )?;

    let res = Response::new()
        .add_message(msg)
        .add_attribute("action", "swap")
        .add_attribute("target_chain_id", target_chain_id)
        .add_attribute("target_token", target_token)
        .add_attribute("target_address", target_address)
        .add_attribute("swap_bridge_amount", swap_bridge_amount);
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

#[cfg(test)]
mod test {
    use cosmwasm_std::{
        attr, from_binary, to_binary, BalanceResponse, BankQuery, QueryRequest, Response, Uint128,
    };

    use fiberrouter::{FiberRouterExecuteMsg, FiberRouterQueryMsg, MigrateMsg};

    use crate::error::ContractError;
    use crate::msg::InstantiateMsg;
    use crate::state::OWNER;

    use crate::contract::{
        execute, execute_ownership_transfer, execute_set_pool, execute_swap,
        execute_withdraw_signed, instantiate, migrate, query, query_owner, query_pool, ExecuteEnv,
    };

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MOCK_CONTRACT_ADDR};

    #[test]
    fn test_initialization() {
        let owner = "address_to_be_owner";
        let pool = "address_to_be_pool";
        let deployer = "some_address";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(deployer, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            pool: pool.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        assert_eq!(query_owner(deps.as_ref()).unwrap(), owner.to_string());
        assert_eq!(OWNER.load(&deps.storage).unwrap(), owner.to_string());
        assert_eq!(query_pool(deps.as_ref()).unwrap(), pool.to_string());
    }

    #[test]
    fn test_ownership_transfer() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            pool: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
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
    fn test_execute_ownership_transfer_catch_err_unauthorized() {
        let first_owner = "address_to_be_first_owner";
        let second_owner = "address_to_be_second_owner";
        let pool = "address_to_be_pool";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(first_owner, &[]);
        let msg = InstantiateMsg {
            owner: first_owner.to_string(),
            pool: pool.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
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
    fn test_set_pool() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            owner: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
            pool: "cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym".to_string(),
        };
        let env = mock_env();
        let info = mock_info("cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym", &[]);
        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let eenv = ExecuteEnv {
            deps: deps.as_mut(),
            info: info.clone(),
        };
        execute_set_pool(
            eenv,
            "cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh".to_string(),
        )
        .unwrap();
        let owner = query_pool(deps.as_ref()).unwrap();
        assert_eq!(
            "cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh".to_string(),
            owner
        );
    }

    #[test]
    fn test_execute_set_pool_catch_err_unauthorized() {
        let first_owner = "address_to_be_first_owner";
        let pool = "address_to_be_pool";
        let second_pool = "address_to_be_second_pool";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(first_owner, &[]);
        let msg = InstantiateMsg {
            owner: first_owner.to_string(),
            pool: pool.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            info: mock_info("other_address", &[]),
        };

        assert_eq!(
            execute_set_pool(execute_env, second_pool.to_string())
                .unwrap_err()
                .to_string(),
            (ContractError::Unauthorized {}).to_string()
        );
    }

    #[test]
    fn test_execute_withdraw_signed() {
        let owner = "address_to_be_owner";
        let pool = "address_to_be_pool";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            pool: pool.to_string(),
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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
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
                attr("payee", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(700u128))
            ]
        )
    }

    #[test]
    fn test_execute_swap() {
        let owner = "address_to_be_owner";
        let pool = "address_to_be_pool";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            pool: pool.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(700u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
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
                attr("target_chain_id", "137".to_string()),
                attr("target_token", "token_address_out_chain".to_string()),
                attr("target_address", "user_address_out_chain".to_string()),
                attr("swap_bridge_amount", Uint128::from(10u128)),
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
    fn test_migrate() {
        let owner = "address_to_be_owner";
        let pool = "address_to_be_pool";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            pool: pool.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        let rsp = migrate(deps.as_mut(), env.clone(), MigrateMsg {}).unwrap();
        assert_eq!(rsp, Response::default());
    }

    #[test]
    fn test_execute_query_multitest() {
        let owner = "address_to_be_owner";
        let pool = "address_to_be_pool";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
            pool: pool.to_string(),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        assert_eq!(res.is_err(), false);

        /////////////////////////////////////////////////////////////

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FiberRouterExecuteMsg::TransferOwnership {
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

        let token = "token_address".to_string();
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FiberRouterExecuteMsg::WithdrawSigned {
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
                attr("payee", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", Uint128::from(700u128)),
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
            FiberRouterExecuteMsg::Swap {
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
                attr("target_chain_id", "137".to_string()),
                attr("target_token", "token_address_out_chain".to_string()),
                attr("target_address", "user_address_out_chain".to_string()),
                attr("swap_bridge_amount", Uint128::from(10u128)),
            ]
        );

        let rsp = query(deps.as_ref(), env.clone(), FiberRouterQueryMsg::Owner {}).unwrap();
        assert_eq!(
            rsp.to_string(),
            to_binary(&"address_to_be_owner_2".to_string())
                .unwrap()
                .to_string()
        );

        let rsp = query(deps.as_ref(), env.clone(), FiberRouterQueryMsg::Pool {}).unwrap();
        assert_eq!(
            rsp.to_string(),
            to_binary(&pool.to_string()).unwrap().to_string()
        );
    }
}
