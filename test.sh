#!/bin/sh

# NODE=http://localhost:26657
# VALIDATOR=$(cudos-noded keys show -a validator --keyring-backend=test)
# cudos-noded tx wasm store cw-plus/fundmanager_base.wasm --from=validator --keyring-backend=test --chain-id=test --node http://localhost:26657 --gas=auto --gas-adjustment=1.3 -y
# deploy with admin upgradeable
# cudos-noded tx wasm instantiate 1 '{"owner":"'$VALIDATOR'","fee_collector":"'$VALIDATOR'"}' --from=validator --label "FerrumFundManager" --chain-id=test --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --admin=$VALIDATOR -y
# deploy without admin
# cudos-noded tx wasm instantiate 1 '{"owner":"'$VALIDATOR'","fee_collector":"'$VALIDATOR'"}' --from=validator --label "FerrumFundManager" --chain-id=test --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --no-admin -y
# CONTRACT=cudos14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9strccpl
# cudos-noded tx wasm execute $CONTRACT '{"add_foundry_asset":{"token":"stake"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"remove_foundry_asset":{"token":"stake"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"add_liquidity":{}}' --amount=1000000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"remove_liquidity":{"token":"stake","amount": "100000"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"withdraw_signed":{"payee":"'$VALIDATOR'","token":"stake","amount":"1000","salt":"0x00","signature":"251fa6ca91ade4b0c76712bc8c6fec07d91c0b7466e3f082cbd3cad917c9d9b008832149f8f97adfc20be042bcdc6598a1bebb23a25e30bd5c58db086da18af91b"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"swap":{"target_chain_id":"0x00","target_token":"0x00","target_address":"0x00"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"add_signer":{"signer":"0x0bdb79846e8331a19a65430363f240ec8acc2a52"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"remove_signer":{"signer":"0x0bdb79846e8331a19a65430363f240ec8acc2a52"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"transfer_ownership":{"new_owner":"cudos1nysrj2xxpm77xpkvglne0zcvnxuq0laacc7nrv"}}' --amount=1000stake --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $CONTRACT '{"set_fee":{"token":"stake","fee":"800"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test 
# cudos-noded tx wasm execute $CONTRACT '{"set_fee_collector":{"collector":"cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test 

# cudos-noded query bank balances cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym
# cudos-noded query wasm contract-state smart $CONTRACT '{"fee_collector":{}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"liquidity":{"owner":"'$VALIDATOR'","token":"stake"}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"all_liquidity":{}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"all_liquidity":{"start_after":["acudos", "cudos1syysfe8ryh7ltnpqe9xvf59thdpyqp8x6aewxh"]}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"signers":{}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"signers":{"start_after":"0x1"}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"foundry_assets":{"start_after":"a"}}'
# cudos-noded query wasm contract-state smart $CONTRACT '{"foundry_assets":{}}'

# cudos-noded tx wasm store cw-plus/fundmanager_base.wasm --from=validator --keyring-backend=test --chain-id=test --node=$NODE --gas=auto --gas-adjustment=1.3 -y
# NEW_CODEID=2
# cudos-noded tx wasm migrate $CONTRACT $NEW_CODEID '{}' --from=validator --keyring-backend=test --chain-id=test --node=$NODE --gas=auto --gas-adjustment=1.3 -y

# upgrade ownership transfer
# cudos-noded tx wasm set-contract-admin $CONTRACT $VALIDATOR --from=validator --keyring-backend=test --chain-id=test --node http://localhost:26657 --gas=auto --gas-adjustment=1.3 -y

# deploy fiber router
# cudos-noded tx wasm store cw-plus/fiberrouter_base.wasm --from=validator --keyring-backend=test --chain-id=test --node=$NODE --gas=auto --gas-adjustment=1.3 -y
# instantiate the contract
# cudos-noded tx wasm instantiate 2 '{"owner":"'$VALIDATOR'","pool":"'$CONTRACT'"}' --from=validator --label "FerrumFiberRouter" --chain-id=test --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --admin=$VALIDATOR -y
# FIBER_ROUTER=cudos1zwv6feuzhy6a9wekh96cd57lsarmqlwxdypdsplw6zhfncqw6ftqlnfp2z
# cudos-noded tx wasm execute $FIBER_ROUTER '{"set_pool":{"pool":"'$CONTRACT'"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $FIBER_ROUTER '{"withdraw_signed":{"payee":"'$VALIDATOR'","token":"stake","amount":"1000","salt":"0x00","signature":"0x00"}}' --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded tx wasm execute $FIBER_ROUTER '{"swap":{"target_chain_id":"0x00","target_token":"0x00","target_address":"0x00"}}' --amount=1000stake  --from=validator --gas=auto --gas-adjustment=1.3 --chain-id=test -y --keyring-backend=test
# cudos-noded query wasm contract-state smart $FIBER_ROUTER '{"pool":{}}'
# cudos-noded query bank balances $FIBER_ROUTER
# cudos-noded query bank balances $CONTRACT

# create cudos account
cudos-noded keys add cudosadmin --keyring-backend=test --recover
# ADMIN=cudos167mthp8jzz40f2vjz6m8x2m77lkcnp7nxsk5ym
"tag swift report alcohol cabbage tree round since roof rug snow olive diary beef private into volcano common rocket license hope echo guard crush"
cudos-noded keys add cudosadmin2 --keyring-backend=test --recover
# ADMIN2=cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh
"amused ethics frog april wall faith pull merge system off cost north wrist twice turn visit gun world lucky knee grain onion hope grief"

# NODE=http://sentry1.gcp-uscentral1.cudos.org:26657
# NODE=https://rpc.cudos.org:26657
cudos-noded tx wasm store cw-plus/fundmanager_base.wasm --from=cudosadmin --keyring-backend=test --chain-id=cudos-testnet-public-3 --node=$NODE --gas=auto --gas-adjustment=1.3 -y --fees=18758390000000000000acudos
FUND_MANAGER_CODEID=63
FUND_MANAGER_CODEID=81
cudos-noded tx wasm instantiate $FUND_MANAGER_CODEID '{"owner":"'$ADMIN'"}' --from=cudosadmin --label "FerrumFundManager" --node=$NODE --chain-id=cudos-testnet-public-3 --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --admin=$ADMIN -y --fees=18758390000000000000acudos
FUND_MANAGER=cudos1rqppygyqm358hj4fx0s2warcaa0h7y95jxdwyqwjamekap7f5m7qwex8va
FUND_MANAGER=cudos15w3pznjstqxe35wghccdw6qgqwxce4j85uwvaaqmk9r7qtjamdhs0262qk

cudos-noded tx wasm store cw-plus/fiberrouter_base.wasm --from=cudosadmin --keyring-backend=test --chain-id=cudos-testnet-public-3 --node=$NODE --gas=auto --gas-adjustment=1.3 -y --fees=18758390000000000000acudos
ROUTER_CODEID=64
ROUTER_CODEID=82
cudos-noded tx wasm instantiate $ROUTER_CODEID '{"owner":"'$ADMIN'","pool":"'$FUND_MANAGER'"}' --from=cudosadmin --label "FerrumFiberRouter" --node=$NODE --chain-id=cudos-testnet-public-3 --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test --admin=$ADMIN -y --fees=18758390000000000000acudos
ROUTER=cudos19rwu6mnumphfkawsdgwra62a7a730gf5gckgxrh4r5acv6hggpwqkvkusk
ROUTER=cudos1ejdmju9rx8fw2072uan4mh2uzmn3v50pxge6y8ardrne6y4l66cqx93x5d

# send tokens from ADMIN to ADMIN2
cudos-noded tx bank send cudosadmin cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh 1000000000000000000000acudos --node=$NODE --chain-id=cudos-testnet-public-3 --gas=auto --gas-adjustment=1.3 -b=block --keyring-backend=test -y --fees=18758390000000000000acudos

# multisig account setup
cudos-noded keys add account1 --pubkey <account1-pubkey>
cudos-noded keys add account2 --pubkey <account2-pubkey>

# sign 2 out of 2
cudos-noded keys add multisig --multisig account1,account2 --multisig-threshold 2

# transfer balance to multisig account
cudos-noded tx bank send 

# multisig transaction compose
cudos-noded tx bank send $(cudos-noded keys show multisig -a) cudos1qu6xuvc3jy2m5wuk9nzvh4z57teq8j3p3q6huh 10000000acudos  --generate-only --chain-id=test > multisigtx.json
cudos-noded tx wasm migrate $CONTRACT $NEW_CODEID '{}' --from=$(cudos-noded keys show multisig -a) --chain-id=test --gas=auto --gas-adjustment=1.3 -y > multisigtx.json
cudos-noded tx wasm execute $CONTRACT '{"add_foundry_asset":{"token":"stake"}}' --from=$(cudos-noded keys show multisig -a) --gas=auto --gas-adjustment=1.3 --chain-id=test --generate-only > multisigtx.json
cudos-noded tx wasm execute $CONTRACT '{"remove_foundry_asset":{"token":"stake"}}' --from=$(cudos-noded keys show multisig -a) --gas=auto --gas-adjustment=1.3 --chain-id=test --generate-only > multisigtx.json
cudos-noded tx wasm execute $CONTRACT '{"add_signer":{"signer":"0x0bdb79846e8331a19a65430363f240ec8acc2a52"}}' --amount=1000stake --from=$(cudos-noded keys show multisig -a) --gas=auto --gas-adjustment=1.3 --chain-id=test --generate-only > multisigtx.json
cudos-noded tx wasm execute $CONTRACT '{"remove_signer":{"signer":"0x0bdb79846e8331a19a65430363f240ec8acc2a52"}}' --amount=1000stake --from=$(cudos-noded keys show multisig -a) --gas=auto --gas-adjustment=1.3 --chain-id=test --generate-only > multisigtx.json
cudos-noded tx wasm execute $CONTRACT '{"transfer_ownership":{"new_owner":"cudos1nysrj2xxpm77xpkvglne0zcvnxuq0laacc7nrv"}}' --amount=1000stake --from=$(cudos-noded keys show multisig -a) --gas=auto --gas-adjustment=1.3 --chain-id=test --generate-only > multisigtx.json

# signature from account1
cudos-noded tx sign --from $(cudos-noded keys show -a account1) --multisig $(cudos-noded keys show -a multisig) multisigtx.json --sign-mode amino-json --chain-id=test >> multisigtx-signed-account1.json
# signature from account2
cudos-noded tx sign --from $(cudos-noded keys show -a account2) --multisig $(cudos-noded keys show -a multisig) multisigtx.json --sign-mode amino-json --chain-id=test >> multisigtx-signed-account2.json

# Combine signatures into single transaction
cudos-noded tx multisign --from multisig multisigtx.json multisig multisigtx-signed-account1.json multisigtx-signed-account2.json --chain-id=test > multisigtx-signed.json

# Broadcast transaction
cudos-noded tx broadcast multisigtx-signed.json --chain-id=test
