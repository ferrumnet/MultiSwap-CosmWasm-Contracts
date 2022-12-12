# FIBER Router

`Multiswap` is a cosmwasm implementation of fund manager for multichain swap.

MultiSwap allows users to securely bridge any asset on network 1 for any asset on network 2 at transaction speed. Read the docs here: https://docs.ferrumnetwork.io/ferrum-network-ecosystem/v/multiswap-and-multichain-liquidity-pool-bridge/

MultiSwap is divided into three major parts

1. Fiber Engine: Controls everything
2. Fiber Router: Everything flows through the router, to ensure that there is no external contract interaction with the Fund Manager contract where the majority of Foundry Assets are.
3. Fund Manager Contract: This is where all the Foundry Assets are and also where the MultiSwap nodes will look to settle assets that need to be bridged across chains.

## Base

At the contract initialization stage, contract owner is set. Here owner has permission to add/remove signer, add/remove foundry asset. Signers are the addresses that are generating signatures for withdrawals from the pool.

### Messages

Messages are the transactions that can be accepted by the contract.

#### TransferOwnership

`TransferOwnership` is used to transfer ownership of router contract to another user. This could be individual account or multisig account. This message should be called by contract owner.

```rust
    TransferOwnership {
        new_owner: String,
    }
```

#### AddSigner

`AddSigner` is used to add signers for withdrawals. This message should be called by contract owner.

```rust
    AddSigner {
        signer: String,
    }
```

#### RemoveSigner

`AddSigner` is used to remove signers for withdrawals. This message should be called by contract owner.

```rust
    RemoveSigner {
        signer: String,
    },
```

#### AddFoundryAsset

`AddFoundryAsset` is used to add foundry assets. This message should be called by contract owner.

```rust
    AddFoundryAsset {
        token: String,
    }
```

#### RemoveFoundryAsset

`RemoveFoundryAsset` is used to remove foundry assets. This message should be called by contract owner.

```rust
    RemoveFoundryAsset {
        token: String,
    }
```

#### AddLiquidity

`AddLiquidity` is used to add liquidity to the contract for foundry assets. This message can be called by any user.

```rust
    AddLiquidity {
        token: String,
        amount: Uint128,
    }
```

#### RemoveLiquidity

`RemoveLiquidity` is used to remove liquidity from the contract for foundry assets. This message can be called by any user.

```rust
    RemoveLiquidity {
        token: String,
        amount: Uint128,
    }
```

#### WithdrawSigned

`WithdrawSigned` is used to withdraw from other network to cudos network with signer's signature. This message is routed by FIBER router.

```rust
    WithdrawSigned {
        payee: String,
        salt: String,
        token: String,
        amount: Uint128,
        signature: String,
    }
```

#### Swap

`Swap` is used to swap cudos network token to other network. This message is routed by FIBER router.

```rust
    Swap {
        token: String,
        amount: Uint128,
        target_chain_id: String,
        target_token: String,
        target_address: String,
    }
}
```

### Queries

Queries are utilized to get the state of the contract.

- `Liquidity{ owner: String, token: String }` - returns liquidity of a token put by specific address.
- `AllLiquidity{}` - returns overall liquidity put by all accounts.
- `Owner{}` - returns owner of the contract.
- `Signers{}` - returns owner of the contract.
- `FoundryAssets{}` - returns owner of the contract.

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

#### AddSignerEvent

`AddSignerEvent` is triggered on `AddSigner` message execution.

```rust
/// Tracks signer additions
pub struct AddSignerEvent<'a> {
    pub from: &'a str,
    pub signer: &'a str,
}
```

#### RemoveSignerEvent

`RemoveSignerEvent` is triggered on `RemoveSigner` message execution.

```rust

/// Tracks signer removals
pub struct RemoveSignerEvent<'a> {
    pub from: &'a str,
    pub signer: &'a str,
}
```

#### AddFoundryAssetEvent

`AddFoundryAssetEvent` is triggered on `AddFoundryAsset` message execution.

```rust
/// Tracks foundry asset additions
pub struct AddFoundryAssetEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
}
```

#### RemoveFoundryAssetEvent

`RemoveFoundryAssetEvent` is triggered on `RemoveFoundryAsset` message execution.

```rust
/// Tracks foundry asset removals
pub struct RemoveFoundryAssetEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
}
```

#### AddLiquidityEvent

`AddLiquidityEvent` is triggered on `AddLiquidity` message execution.

```rust
/// Tracks liquidity additions
pub struct AddLiquidityEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
}
```

#### RemoveLiquidityEvent

`RemoveLiquidityEvent` is triggered on `RemoveLiquidity` message execution.

```rust

/// Tracks liquidity removals
pub struct RemoveLiquidityEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
}
```

#### BridgeSwapEvent

`BridgeSwapEvent` is triggered on `BridgeSwap` message execution.

```rust

/// Tracks swap events
pub struct BridgeSwapEvent<'a> {
    pub from: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
    pub target_chain_id: &'a str,
    pub target_token: &'a str,
    pub target_address: &'a str,
}
```

#### BridgeWithdrawSignedEvent

`BridgeWithdrawSignedEvent` is triggered on `WithdrawSigned` message execution.

```rust

/// Tracks withdraw signed events
pub struct BridgeWithdrawSignedEvent<'a> {
    pub from: &'a str,
    pub payee: &'a str,
    pub token: &'a str,
    pub amount: Uint128,
    pub salt: &'a str,
    pub signature: &'a str,
}
```
