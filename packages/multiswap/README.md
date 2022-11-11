# Multiswap Spec

CW1155 is a specification for managing multiple tokens based on CosmWasm.
The name and design is based on Ethereum's ERC1155 standard.

The specification is split into multiple sections, a contract may only
implement some of this functionality, but must implement the base.

Fungible tokens and non-fungible tokens are treated equally, non-fungible tokens just have one max supply.

Approval is set or unset to some operator over entire set of tokens. (More nuanced control is defined in
[ERC1761](https://eips.ethereum.org/EIPS/eip-1761))

## Base

### Messages

`SendFrom{from, to, token_id, value, msg}` - This transfers some amount of tokens between two accounts. If `to` is an
address controlled by a smart contract, it must implement the `CW1155Receiver` interface, `msg` will be passed to it
along with other fields, otherwise, `msg` should be `None`. The operator should either be the `from` account or have
approval from it.

`BatchSendFrom{from, to, batch: Vec<(token_id, value)>, msg}` - Batched version of `SendFrom` which can handle multiple
types of tokens at once.

`Mint {to, token_id, value, msg}` - This mints some tokens to `to` account, If `to` is controlled by a smart contract,
it should implement `CW1155Receiver` interface, `msg` will be passed to it along with other fields, otherwise, `msg`
should be `None`.

`BatchMint {to, batch: Vec<(token_id, value)>, msg}` - Batched version of `Mint`.

`Burn {from, token_id, value}` - This burns some tokens from `from` account.

`BatchBurn {from, batch: Vec<(token_id, value)>}` - Batched version of `Burn`.

`ApproveAll{ operator, expires }` - Allows operator to transfer / send any token from the owner's account. If expiration
is set, then this allowance has a time/height limit.

`RevokeAll { operator }` - Remove previously granted ApproveAll permission

### Queries

`Balance { owner, token_id }` - Query the balance of `owner` on particular type of token, default to `0` when record not
exist.

`BatchBalance { owner, token_ids }` - Query the balance of `owner` on multiple types of tokens, batched version of
`Balance`.

`ApprovedForAll{owner, include_expired, start_after, limit}` - List all operators that can access all of the owner's
tokens. Return type is `ApprovedForAllResponse`. If `include_expired` is set, show expired owners in the results,
otherwise, ignore them.

`IsApprovedForAll{owner, operator}` - Query approved status `owner` granted to `operator`. Return type is
`IsApprovedForAllResponse`.

### Events

- `transfer(from, to, token_id, value)`

  `from`/`to` are optional, no `from` attribute means minting, no `to` attribute means burning, but they mustn't be
  neglected at the same time.
