use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;
use cosmwasm_std::{Coin, Uint128};
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Cw20Coin {
    pub address: String,
    pub amount: Uint128,
    pub denom: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Amount {
    Native(Coin),
    // FIXME? USe Cw20CoinVerified, and validate cw20 addresses
    Cw20(Cw20Coin),
}

impl Amount {
    pub fn from_parts(denom: String, amount: Uint128) -> Self {
        if denom.starts_with("cw20:") {
            let parts: Vec<&str> = denom.splitn(3, ':').collect();
            let address = parts[1].to_string();
            let denom = parts[2].to_string();
            Amount::Cw20(Cw20Coin {
                address,
                amount,
                denom,
            })
        } else {
            Amount::Native(Coin { denom, amount })
        }
    }

    pub fn cw20(amount: u128, addr: &str, denom: &str) -> Self {
        Amount::Cw20(Cw20Coin {
            address: addr.into(),
            amount: Uint128::new(amount),
            denom: denom.into(),
        })
    }

    pub fn native(amount: u128, denom: &str) -> Self {
        Amount::Native(Coin {
            denom: denom.to_string(),
            amount: Uint128::new(amount),
        })
    }
}

impl Amount {
    pub fn denom(&self) -> String {
        match self {
            Amount::Native(c) => c.denom.clone(),
            Amount::Cw20(c) => format!("cw20:{}:{}", c.address.as_str(), c.denom.as_str()),
        }
    }

    pub fn amount(&self) -> Uint128 {
        match self {
            Amount::Native(c) => c.amount,
            Amount::Cw20(c) => c.amount,
        }
    }

    /// convert the amount into u64
    pub fn u64_amount(&self) -> Result<u64, ContractError> {
        Ok(self.amount().u128().try_into()?)
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Amount::Native(c) => c.amount.is_zero(),
            Amount::Cw20(c) => c.amount.is_zero(),
        }
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::Uint128;
    use crate::amount::Amount;

    #[test]
    fn parse_amount() {
        // native denom
        let res = Amount::from_parts("ucosm".to_string(), 1u8.into());

        assert_eq!("ucosm", res.denom());
        assert_eq!(Uint128::new(1), res.amount());

        // cw20 token
        let res = Amount::from_parts("cw20:my-token:denom".to_string(), 1u8.into());

        assert_eq!("cw20:my-token:denom", res.denom());
        assert_eq!(Uint128::new(1), res.amount());
    }
}
