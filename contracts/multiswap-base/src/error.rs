use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("NotFoundryAsset")]
    NotFoundryAsset {},

    #[error("InvalidSigner")]
    InvalidSigner,

    #[error("UsedSalt")]
    UsedSalt {},

    #[error("InvalidDeposit")]
    InvalidDeposit {},

    #[error("NotValidLowerCaseEthAddress")]
    NotValidLowerCaseEthAddress,

    #[error("InvalidFeeRange")]
    InvalidFeeRange,

    #[error("InvalidTargetInfo")]
    InvalidTargetInfo,

    #[error("InvalidToken")]
    InvalidToken,

    #[error("InvalidAmount")]
    InvalidAmount,
}
