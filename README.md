# MultiSwap CosmWasm Contracts

## Contracts

Ferrum cudos multiswap consists of `Multiswap` and `FiberRouter` contracts.

### Multiswap

`Multiswap` is a fund manager contract for cudos side fund management.

[Spec](./packages/multiswap/README.md)

### FiberRouter

`FiberRouter` is the contract that users interact with for swap and withdrawal operations.

[Spec](./packages/fiberrouter/README.md)

## Local build

```
cargo build
```

## Compiling

To compile all the contracts, run the following in the repo root:

```
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/workspace-optimizer:0.12.6
```

This will compile all packages in the `contracts` directory and output the
stripped and optimized wasm code under the `artifacts` directory as output,
along with a `checksums.txt` file.

If you hit any issues there and want to debug, you can try to run the
following in each contract dir:
`RUSTFLAGS="-C link-arg=-s" cargo build --release --target=wasm32-unknown-unknown --locked`

### Fix for "failed to fetch `https://github.com/rust-lang/crates.io-index`"

https://github.com/rust-lang/cargo/issues/3381#issuecomment-308460530

```
eval `ssh-agent -s`
ssh-add
cargo build
```

## Unit test

To run overall tests:

```
cargo test
```

To run specific test:

```
cargo test <test-name>
```

## Quality Control

One of the basic metrics of assurance over code quality is how much is covered by
unit tests. There are several tools available for Rust to do such analysis and
we will describe one below. This should be used as a baseline metric to give some
confidence in the code.

Beyond code coverage metrics, just having a robust PR review process with a few
more trained eyes looking for bugs is very helpful in detecting paths the original
coder was not aware of. This is more subjective, but looking at the relevant PRs
and depth of discussion can give an idea how much review was present.

After that, fuzzing it (ideally with an intelligent fuzzer that understands the domain)
can be valuable. And beyond that formal verification can provide even more assurance
(but is very time-consuming and expensive).

### Code Coverage

[tarpaulin](https://github.com/xd009642/tarpaulin): `cargo install cargo-tarpaulin`

To get some nice interactive charts, you can go to the root directory and run:

`cargo tarpaulin -o html`
and then `xdg-open tarpaulin-report.html` (or just `open` on MacOS).

Once you find a package that you want to improve, you can do the following to just
analyze this package, which gives much faster turn-around:

`cargo tarpaulin -o html --packages cw3-fixed-multisig`

Note that it will produce a code coverage report for the entire project, but only the coverage in that
package is the real value. If does give quick feedback for you if you unit test writing was successful.

**Commands:**

```
cargo install cargo-tarpaulin

# this print out info on all files in all crates
cargo tarpaulin -v

# this still covers all crates (how to disable workspace?) but also shows html overview
cargo tarpaulin -v --lib -o html
open tarpaulin-report.html

# this seems to run tests in each crate one after another and get better coverage for all packages
cargo tarpaulin -v --lib --workspace -o html
open tarpaulin-report.html
```

**Result of coverage check:**

```
|| Uncovered Lines:
|| contracts/fiberrouter-base/src/contract.rs: 17, 23, 25-26, 28-29, 40, 46-49, 51, 53-58, 60-64, 66-71, 76, 80-81, 84-85, 88-89, 92-93, 95-96, 99-101, 104-105, 108-109, 112-113, 115-116, 119, 127-129, 132, 134-140, 142, 145-146, 148-151, 154, 162-164, 166, 168-174, 176, 179-180, 182-187, 191-194, 198-200, 203-205, 209-210
|| contracts/multiswap-base/src/contract.rs: 45, 51-54, 56-61, 63-64, 66-67, 70-75, 77-81, 83-88, 102, 128, 152, 179, 204, 229, 255, 261, 264, 267, 277-279, 311, 331, 353, 373, 378, 427, 430, 453, 473, 476, 479, 533-536, 538-539, 541-543, 545-546, 548, 557-561, 571, 574, 579, 590, 595-599, 605, 611-613, 615-620, 626-633, 653, 674, 677, 683-684, 686-691, 693, 695, 706-707
|| packages/fiberrouter/src/event.rs: 11-14, 25-28
|| packages/multiswap/src/helpers.rs: 14-15, 18, 23-27, 29
|| packages/multiswap/src/query.rs: 39-43
|| Tested/Total Lines:
|| contracts/fiberrouter-base/src/contract.rs: 0/103 +0.00%
|| contracts/multiswap-base/src/contract.rs: 253/368 +0.00%
|| packages/fiberrouter/src/event.rs: 0/8 +0.00%
|| packages/multiswap/src/event.rs: 54/54 +0.00%
|| packages/multiswap/src/helpers.rs: 0/9 +0.00%
|| packages/multiswap/src/query.rs: 0/5 +0.00%
||
56.12% coverage, 307/547 lines covered, +0.00% change in coverage
```
