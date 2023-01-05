# MultiSwap CosmWasm Contracts

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

I recommend the use of [tarpaulin](https://github.com/xd009642/tarpaulin): `cargo install cargo-tarpaulin`

To get some nice interactive charts, you can go to the root directory and run:

`cargo tarpaulin -o html`
and then `xdg-open tarpaulin-report.html` (or just `open` on MacOS).

Once you find a package that you want to improve, you can do the following to just
analyze this package, which gives much faster turn-around:

`cargo tarpaulin -o html --packages cw3-fixed-multisig`

Note that it will produce a code coverage report for the entire project, but only the coverage in that
package is the real value. If does give quick feedback for you if you unit test writing was successful.
