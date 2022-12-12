# FIBER Router

FIBER Router is a cosmwasm implementation of FIBER router engine.

MultiSwap allows users to securely bridge any asset on network 1 for any asset on network 2 at transaction speed. Read the docs here: https://docs.ferrumnetwork.io/ferrum-network-ecosystem/v/multiswap-and-multichain-liquidity-pool-bridge/

MultiSwap is divided into three major parts

1. Fiber Engine: Controls everything
2. Fiber Router: Everything flows through the router, to ensure that there is no external contract interaction with the Fund Manager contract where the majority of Foundry Assets are.
3. Fund Manager Contract: This is where all the Foundry Assets are and also where the MultiSwap nodes will look to settle assets that need to be bridged across chains.

## Base

At the contract initialization stage, contract owner and pool are set. Here owner has permission to set pool and pool contract is used by router contract to redirect users' swap and withdrawals to the contract.

### Messages

Messages are the transactions that can be accepted by the contract.

#### TransferOwnership

`TransferOwnership` is used to transfer ownership of router contract to another user. This could be individual account or multisig account. This message should be called by contract owner.

```rust
    TransferOwnership {
        new_owner: String,
    }
```

#### SetPool

`TransferOwnership` is used to update pool contract to anther contract. This message could be called by contract owner.

```rust
    SetPool {
        pool: String,
    },
```

#### Swap

`Swap` is used to initiate token swap from cudos network to another network. It can be called by any user.

```rust
    Swap {
        token: String,
        amount: Uint128,
        target_chain_id: String,
        target_token: String,
        target_address: String,
    }
```

#### WithdrawSigned

`WithdrawSigned` is used to finalized withdrawal of tokens from other network to cudos network. This can be called by any user and it requires signature from a signer.

```rust
    WithdrawSigned {
        payee: String,
        salt: String,
        token: String,
        amount: Uint128,
        signature: String,
    }
```

### Queries

Queries are utilized to get the state of the contract.

- `Owner{}` - returns the address of contract owner.
- `Pool{}` - returns the address of configured pool for the router contract.

### Events

Events are triggered from the contract to put the state transition logs of the contract.

#### TransferOwnershipEvent

`TransferOwnershipEvent` is triggered on `TransferOwnership` message execution.

```rust
pub struct TransferOwnershipEvent<'a> {
    pub prev_owner: &'a str,
    pub new_owner: &'a str,
}
```

#### SetPoolEvent

`SetPoolEvent` is triggered on `SetPool` message execution.

```rust
pub struct SetPoolEvent<'a> {
    pub from: &'a str,
    pub pool: &'a str,
}
```
