#[cfg(test)]
mod test {
    use cosmwasm_std::entry_point;
    use cosmwasm_std::{
        attr, coins, from_binary, to_binary, Addr, AllBalanceResponse, Api, BalanceResponse,
        BankMsg, BankQuery, Binary, CosmosMsg, CustomQuery, Deps, DepsMut, Env, MessageInfo, Order,
        QueryRequest, Response, StdError, StdResult, Storage, Uint128, WasmQuery,
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
    use sha3::{Digest, Keccak256};
    use std::convert::TryInto;

    use crate::contract::{
        add_used_message, ethereum_address_raw, execute, execute_add_foundry_asset,
        execute_add_liquidity, execute_add_signer, execute_ownership_transfer,
        execute_remove_foundry_asset, execute_remove_liquidity, execute_remove_signer,
        execute_set_fee, execute_swap, execute_withdraw_signed, get_signer, instantiate,
        is_foundry_asset, is_signer, is_used_message, migrate, query, query_all_liquidity,
        query_fee, query_foundry_assets, query_liquidity, query_owner, query_signers,
        read_foundry_assets, read_liquidities, read_signers, ExecuteEnv,
    };

    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
        MOCK_CONTRACT_ADDR,
    };

    #[test]
    fn test_initialization() {
        let owner = "address_to_be_owner";
        let deployer = "some_address";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(deployer, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        let rsp = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        assert_eq!(query_owner(deps.as_ref()).unwrap(), owner.to_string());
        assert_eq!(OWNER.load(&deps.storage).unwrap(), owner.to_string());

        // assert_eq!(
        //     rsp.attributes,
        //     vec![]
        // );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(owner, &[]),
        };

        let rsp = read_signers(&deps.storage, None, None);
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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_ownership_transfer(execute_env, second_owner.to_string()).unwrap();

        assert_eq!(
            query_owner(deps.as_ref()).unwrap(),
            second_owner.to_string()
        );
        assert_eq!(OWNER.load(&deps.storage).unwrap(), second_owner.to_string());

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "transfer_ownership".to_string()),
                attr("prev_owner", first_owner.to_string()),
                attr("new_owner", second_owner.to_string())
            ]
        );
    }

    #[test]
    fn test_execute_ownership_transfer__catch_err_unauthorized() {
        let first_owner = "address_to_be_first_owner";
        let second_owner = "address_to_be_second_owner";

        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(first_owner, &[]);
        let msg = InstantiateMsg {
            owner: first_owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

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
    fn test_execute_set_fee() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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

        let query_res = query_fee(deps.as_ref(), "token_address".to_string()).unwrap();
        assert_eq!(query_res.token, "token_address".to_string());
        assert_eq!(query_res.amount, Uint128::from(1u128));

        // ! assert_eq!(
        //     rsp.attributes,
        //     vec![
        //         attr("action", "set_fee".to_string()),
        //         attr("amount", Uint128::from(1u128)),
        //         attr("token", "token_address".to_string()),
        //         attr("from", owner.to_string())
        //     ]
        // );
    }

    #[test]
    fn test_execute_set_fee__catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

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
    fn test_execute_set_fee__catch_err_invalid_token_address() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
    fn test_execute_set_fee__catch_err_invalid_range_fee() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );

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
    fn test_execute_add_signer__catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
    fn test_execute_add_signer__catch_err_invalid_ethereum_address() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );

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
    fn test_execute_remove_signer__catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );

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
    fn test_execute_remove_signer__catch_err_not_signer() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );

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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address".to_string());
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
    fn test_execute_add_foundry_asset__catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
    fn test_execute_add_foundry_asset__catch_err_invalid_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address_2".to_string());
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
    fn test_execute_remove_foundry_asset__catch_err_unauthorized() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address_2".to_string());
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
    fn test_execute_remove_foundry_asset__catch_err_invalid_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address_2".to_string());
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
    fn test_execute_remove_foundry_asset__catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address".to_string());
        assert_eq!(
            is_foundry_asset(&deps.storage, "token_address".to_string()),
            true
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, "token_address_2".to_string());
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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());
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
    fn test_execute_add_liquidity__catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

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
    fn test_execute_add_liquidity__catch_err__invalid_deposit_if_more_1_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());
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

    // #[test]
    // fn test_execute_add_liquidity__catch_err__invalid_deposit_if_tokens_mismatched() {
    //     let owner = "address_to_be_owner";
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     let info = mock_info(owner, &[]);
    //     let msg = InstantiateMsg {
    //         owner: owner.to_string(),
    //     };

    //     instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

    //     /////////////////////////////////////////////////////////////

    //     let token = "token_address".to_string();
    //     let amount = Uint128::from(1000u128);

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: info.clone(),
    //     };

    //     execute_add_foundry_asset(execute_env, token.clone());

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: info.clone(),
    //     };

    //     execute_add_foundry_asset(execute_env, "other_token".to_string());

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: mock_info(
    //             owner,
    //             &[
    //                 cosmwasm_std::Coin {
    //                     denom: token.clone(),
    //                     amount: amount,
    //                 },
    //             ]
    //         ),
    //     };

    //     assert_eq!(
    //         execute_add_liquidity(execute_env, "other_token".to_string(), amount)
    //             .unwrap_err()
    //             .to_string(),
    //         (ContractError::InvalidDeposit {}).to_string()
    //     );
    // }

    // #[test]
    // fn test_execute_add_liquidity__catch_err__invalid_deposit_if_amounts_mismatched() {
    //     let owner = "address_to_be_owner";
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     let info = mock_info(owner, &[]);
    //     let msg = InstantiateMsg {
    //         owner: owner.to_string(),
    //     };

    //     instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

    //     /////////////////////////////////////////////////////////////

    //     let token = "token_address".to_string();
    //     let amount = Uint128::from(1000u128);

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: info.clone(),
    //     };

    //     execute_add_foundry_asset(execute_env, token.clone());

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: mock_info(
    //             owner,
    //             &[
    //                 cosmwasm_std::Coin {
    //                     denom: token.clone(),
    //                     amount: amount,
    //                 },
    //             ]
    //         ),
    //     };

    //     assert_eq!(
    //         execute_add_liquidity(execute_env, token.clone(), Uint128::from(1234u128))
    //             .unwrap_err()
    //             .to_string(),
    //         (ContractError::InvalidDeposit {}).to_string()
    //     );
    // }

    #[test]
    fn test_execute_remove_liquidity() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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

        execute_add_liquidity(execute_env);

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
    fn test_execute_remove_liquidity__catch_err__not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

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
    fn test_execute_remove_liquidity__catch_err__liquidity_does_not_exist() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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

        execute_add_liquidity(execute_env);

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
    fn test_execute_remove_liquidity__catch_err__invalid_token() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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

        execute_add_liquidity(execute_env);

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
    fn test_execute_remove_liquidity__catch_err__zero_amount() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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

        execute_add_liquidity(execute_env);

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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        execute_add_signer(execute_env, signer.to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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
    fn test_execute_withdraw_signed__catch_err_invalid_token_address() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        execute_add_signer(execute_env, signer.to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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
    fn test_execute_withdraw_signed__catch_err_zero_amount() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        execute_add_signer(execute_env, signer.to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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
    fn test_execute_withdraw_signed__catch_err_not_foundry_asset() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        execute_add_signer(execute_env, signer.to_string());

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
    fn test_execute_withdraw_signed__catch_err_invalid_signer() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd66ea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194bba41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        // execute_add_signer(execute_env, signer.to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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
    fn test_execute_withdraw_signed__catch_err_used_salt() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        // let signer = "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string();
        let token = "token_address".to_string();
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd66ea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194bba41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        execute_add_signer(execute_env, signer.to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        add_used_message(&mut deps.storage, salt.clone());

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
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(700u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute_set_fee(execute_env, token.clone(), Uint128::from(2000u128)).unwrap();

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
        )
        .unwrap();

        assert_eq!(
            rsp.attributes,
            vec![
                attr("action", "swap".to_string()),
                attr("from", owner.to_string()),
                attr("token", token.clone()),
                attr("amount", amount),
                attr("target_chain_id", "137".to_string()),
                attr("target_token", "token_address_out_chain".to_string()),
                attr("target_address", "user_address_out_chain".to_string()),
                // ! ISSUE
                // ! attr("fee_amount", "140".to_string()),
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
    fn test_execute_swap__catch_err_more_1_fund() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(777u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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
                "user_address_out_chain".to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidDeposit {}).to_string()
        );
    }

    #[test]
    fn test_execute_swap__catch_err_invalid_target_info() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let token = "token_address".to_string();
        let amount = Uint128::from(777u128);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_foundry_asset(execute_env, token.clone());

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
                "user_address_out_chain".to_string()
            )
            .unwrap_err()
            .to_string(),
            (ContractError::InvalidTargetInfo {}).to_string()
        );
    }

    // #[test]
    // fn test_execute_swap__catch_err_tokens_mismatched() {
    //     let owner = "address_to_be_owner";
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     let info = mock_info(owner, &[]);
    //     let msg = InstantiateMsg {
    //         owner: owner.to_string(),
    //     };

    //     instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

    //     /////////////////////////////////////////////////////////////

    //     let token = "token_address".to_string();
    //     let amount = Uint128::from(777u128);

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: info.clone(),
    //     };

    //     execute_add_foundry_asset(execute_env, token.clone());

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: mock_info(
    //             owner,
    //             &[
    //                 cosmwasm_std::Coin {
    //                     denom: "token_address_2".to_string(),
    //                     amount: amount,
    //                 },
    //             ]
    //         ),
    //     };

    //     assert_eq!(
    //         execute_swap(
    //             execute_env,
    //             "137".to_string(),
    //             "token_address_out_chain".to_string(),
    //             "user_address_out_chain".to_string()
    //         )
    //             .unwrap_err()
    //             .to_string(),
    //         (ContractError::InvalidDeposit {}).to_string()
    //     );
    // }

    // #[test]
    // fn test_execute_swap__catch_err_amounts_mismatched() {
    //     let owner = "address_to_be_owner";
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     let info = mock_info(owner, &[]);
    //     let msg = InstantiateMsg {
    //         owner: owner.to_string(),
    //     };

    //     instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

    //     /////////////////////////////////////////////////////////////

    //     let token = "token_address".to_string();
    //     let amount = Uint128::from(777u128);

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: info.clone(),
    //     };

    //     execute_add_foundry_asset(execute_env, token.clone());

    //     let execute_env = ExecuteEnv {
    //         deps: deps.as_mut(),
    //         env: env.clone(),
    //         info: mock_info(
    //             owner,
    //             &[
    //                 cosmwasm_std::Coin {
    //                     denom: token.clone(),
    //                     amount: Uint128::from(666u128),
    //                 },
    //             ]
    //         ),
    //     };

    //     assert_eq!(
    //         execute_swap(
    //             execute_env,
    //             "137".to_string(),
    //             "token_address_out_chain".to_string(),
    //             "user_address_out_chain".to_string()
    //         )
    //             .unwrap_err()
    //             .to_string(),
    //         (ContractError::InvalidDeposit {}).to_string()
    //     );
    // }

    #[test]
    fn test_execute_query_multitest() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        let query_res = query_fee(deps.as_ref(), "token_address".to_string()).unwrap();
        assert_eq!(query_res.token, "token_address".to_string());
        assert_eq!(query_res.amount, Uint128::from(22u128));

        // ! ISSUE
        // ! assert_eq!(
        //     rsp.attributes,
        //     vec![
        //         attr("action", "add_signer".to_string()),
        //         attr("amount", Uint128::from(22u128)),
        //         attr("token", "token_address".to_string()),
        //         attr("from", owner.to_string())
        //     ]
        // );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_add_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f13f".to_string(),
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            FundManagerExecuteMsg::AddFoundryAsset {
                token: "token_address_mock".to_string(),
            },
        )
        .unwrap();

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: "token_address".to_string(),
                    amount: Uint128::from(22u128),
                }],
            ),
        };

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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
        let amount = Uint128::from(1000u128);
        let salt = "salt".to_string();
        let signature =
            "dada130255a447ecf434a2df9193e6fbba663e4546c35c075cd6eea21d8c7cb1714b9b65a4f7f604ff6aad55fba73f8c36514a512bbbba03709b37069194f8a41b";

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

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

        execute_add_signer(execute_env, signer.to_string());

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

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: mock_info(
                owner,
                &[cosmwasm_std::Coin {
                    denom: token.clone(),
                    amount: Uint128::from(777u128),
                }],
            ),
        };

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
        );

        // assert_eq!(Liquidity::to_normal(rsp, &deps.api), "token_address".to_string());
        // assert_eq!(rsp.amount, Uint128::from(12u128));

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

        // assert_eq!();

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::AllLiquidity {
                start_after: None,
                limit: None,
            },
        )
        .unwrap();

        // assert_eq!();

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::Signers {
                start_after: None,
                limit: None,
            },
        )
        .unwrap();

        // assert_eq!();

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::FoundryAssets {
                start_after: None,
                limit: None,
            },
        )
        .unwrap();

        // assert_eq!();

        let rsp = query(
            deps.as_ref(),
            env.clone(),
            FundManagerQueryMsg::Fee {
                token: token.clone(),
            },
        )
        .unwrap();

        // assert_eq!();

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

        execute_remove_signer(
            execute_env,
            "0x8929cbb11fdd5798db5f638a5002235c6412f26a".to_string(),
        );

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = read_signers(&deps.storage, None, None);

        // assert_eq!(rsp.to_string(), "".to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_remove_signer(execute_env, signer.to_string());

        let rsp = read_signers(&deps.storage, None, None);

        // assert_eq!(rsp.to_string(), "".to_string());

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        execute_remove_foundry_asset(execute_env, "token_address".to_string());

        let rsp = read_foundry_assets(&deps.storage, None, None);

        // assert_eq!(rsp.to_string(), "".to_string());
    }

    #[test]
    fn test_migrate() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        /////////////////////////////////////////////////////////////

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        let rsp = migrate(deps.as_mut(), env.clone(), MigrateMsg {}).unwrap();

        assert_eq!(rsp, Response::default());
    }

    #[test]
    fn test_ethereum_address_raw() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let signer = "0x910266349a2aaca44ce909b6845e8c1ab75f475e".to_string();
        let mut pubkey_vec: Vec<u8> = Vec::from([
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
    fn test_ethereum_address_raw__catch_err_empty_key() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let signer = "0x910266349a2aaca44ce909b6845e8c1ab75f475e".to_string();
        let mut pubkey_vec: Vec<u8> = Vec::from([]);

        assert_eq!(
            ethereum_address_raw(&pubkey_vec).unwrap_err().to_string(),
            "Generic error: Public key must not be empty".to_string()
        );
    }

    #[test]
    fn test_ethereum_address_raw__catch_err_invalid_key() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let signer = "0x910266349a2aaca44ce909b6845e8c1ab75f475e".to_string();
        let mut pubkey_vec: Vec<u8> = Vec::from([
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
    fn test_ethereum_address_raw__catch_err_invalid_length() {
        let owner = "address_to_be_owner";
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: owner.to_string(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg);

        let execute_env = ExecuteEnv {
            deps: deps.as_mut(),
            env: env.clone(),
            info: info.clone(),
        };

        // 0x910266349a2aaca44ce909b6845e8c1ab75f475e
        // [4, 66, 91, 185, 143, 51, 145, 149, 174, 15, 8, 226, 58, 172, 220, 172, 176, 8, 58, 211, 123, 186, 203, 240, 64, 112, 233, 120, 16, 129, 196, 206, 212, 201, 204, 154, 66, 211, 181, 116, 10, 250, 253, 162, 211, 110, 216, 254, 162, 49, 63, 48, 133, 29, 153, 127, 95, 97, 178, 42, 20, 244, 83, 87, 235]
        let signer = "0x910266349a2aaca44ce909b6845e8c1ab75f475e".to_string();
        let mut pubkey_vec: Vec<u8> = Vec::from([
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
