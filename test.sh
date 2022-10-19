#!/bin/sh

# VALIDATOR=$(cudos-noded keys show -a validator --keyring-backend=test)
# cudos-noded tx wasm store cw-plus/multiswap_base_v1.wasm --from=validator --keyring-backend=test --chain-id=test --node http://localhost:26657 --gas=auto --gas-adjustment=1.3 -y
# deploy with admin upgradeable
# cudos-noded tx wasm instantiate 1 '{"owner":"'$VALIDATOR'"}' --from=validator --label "FerrumMultiswap" --chain-id=test --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --admin=$VALIDATOR -y
# deploy without admin
# cudos-noded tx wasm instantiate 1 '{"owner":"'$VALIDATOR'"}' --from=validator --label "FerrumMultiswap" --chain-id=test --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --no-admin -y
# CONTRACT=cudos14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9strccpl
# cudos-noded tx wasm execute $CONTRACT '{"add_liquidity":{"token":"stake","amount": "1000000"}}' --amount=1000000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"remove_liquidity":{"token":"stake","amount": "100000"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"withdraw_signed":{"payee":"'$VALIDATOR'","token":"stake","amount":"1000","salt":"0x00","signature":"0x00"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"swap":{"token":"stake","amount":"1000","target_chain_id":"0x00","target_token":"0x00","target_address":"0x00"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"add_signer":{"signer":"cudos1jlm87kyvr668u5d593mdlrfuwf0t2z0x3ct9th"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"remove_signer":{"signer":"cudos1jlm87kyvr668u5d593mdlrfuwf0t2z0x3ct9th"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"transfer_ownership":{"new_owner":"cudos1jlm87kyvr668u5d593mdlrfuwf0t2z0x3ct9th"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test

# cudos-noded query wasm contract-state smart $CONTRACT '{"liquidity":{"owner":"'$VALIDATOR'","token":"stake"}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"all_liquidity":{}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"signers":{}}'

# cudos-noded tx wasm store cw-plus/multiswap_base.wasm --from=validator --keyring-backend=test --chain-id=test --node http://localhost:26657 --gas=auto --gas-adjustment=1.3 -y
# NEW_CODEID=2
# cudos-noded tx wasm migrate $CONTRACT $NEW_CODEID '{}' --from=validator --keyring-backend=test --chain-id=test --node http://localhost:26657 --gas=auto --gas-adjustment=1.3 -y

# upgrade ownership transfer
# cudos-noded tx wasm set-contract-admin $CONTRACT $VALIDATOR --from=validator --keyring-backend=test --chain-id=test --node http://localhost:26657 --gas=auto --gas-adjustment=1.3 -y
