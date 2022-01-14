#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, IbcMsg, IbcQuery, MessageInfo,
    Order, PortIdResponse, Response, StdResult,
};

use cw2::{get_contract_version, set_contract_version};
use cw20::Cw20ReceiveMsg;
use cw_storage_plus::Bound;

use crate::amount::{Amount, Cw20Coin};
use crate::error::ContractError;
use crate::ibc::Ics20Packet;
use crate::msg::{
    AdminResponse, AllContractsResponse, ChannelResponse, ExecuteMsg, HasContractResponse, InitMsg,
    ListChannelsResponse, MigrateMsg, PortResponse, QueryMsg, TransferMsg,
};
use crate::state::{Config, ContractInfo, CHANNEL_INFO, CHANNEL_STATE, CONFIG, CONTRACTS_INFO};
use cw_utils::{nonpayable, one_coin};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw20-ics20";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    let cfg = Config {
        admin: info.sender.to_string(),
        default_timeout: msg.default_timeout,
    };
    CONFIG.save(deps.storage, &cfg)?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let api = deps.api;
    match msg {
        ExecuteMsg::UpdateAdmin { admin } => execute_update_admin(
            deps,
            info,
            admin.map(|admin| api.addr_validate(&admin)).transpose()?,
        ),
        ExecuteMsg::RegisterCw20 { contract, denom } => {
            execute_register_cw20(deps, info, contract, denom)
        }
        ExecuteMsg::Receive(msg) => execute_receive(deps, env, info, msg),
        ExecuteMsg::Transfer(msg) => {
            let coin = one_coin(&info)?;
            execute_transfer(deps, env, msg, Amount::Native(coin), info.sender)
        }
    }
}

pub fn execute_update_admin(
    deps: DepsMut,
    info: MessageInfo,
    new_admin: Option<Addr>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.admin != info.sender {
        return Err(ContractError::NotAdmin {});
    }

    let admin_str = match new_admin.as_ref() {
        Some(admin) => admin.to_string(),
        None => "None".to_string(),
    };
    CONFIG.update(deps.storage, |mut c| -> StdResult<_> {
        c.admin = admin_str.clone();
        Ok(c)
    })?;

    let attributes = vec![
        attr("action", "update_admin"),
        attr("admin", admin_str),
        attr("sender", info.sender),
    ];

    Ok(Response::new().add_attributes(attributes))
}

pub fn execute_register_cw20(
    deps: DepsMut,
    info: MessageInfo,
    contract: String,
    denom: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.admin != info.sender {
        return Err(ContractError::NotAdmin {});
    }

    let cw20_addr = deps.api.addr_validate(&contract)?;
    let data = ContractInfo { denom };
    CONTRACTS_INFO.save(deps.storage, &cw20_addr, &data)?;

    let attributes = vec![
        attr("action", "register_cw20"),
        attr("cw20_contract", cw20_addr),
        attr("denom", data.denom),
    ];

    Ok(Response::new().add_attributes(attributes))
}

pub fn execute_receive(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    wrapper: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    let msg: TransferMsg = from_binary(&wrapper.msg)?;
    let cw20_contract = info.sender;
    let contract = CONTRACTS_INFO
        .may_load(deps.storage, &cw20_contract)?
        .ok_or(ContractError::NoContractAllowed {
            contract: cw20_contract.clone().into(),
        })?;

    let amount = Amount::Cw20(Cw20Coin {
        address: cw20_contract.into(),
        amount: wrapper.amount,
        denom: contract.denom,
    });
    let api = deps.api;
    execute_transfer(deps, env, msg, amount, api.addr_validate(&wrapper.sender)?)
}

pub fn execute_transfer(
    deps: DepsMut,
    env: Env,
    msg: TransferMsg,
    amount: Amount,
    sender: Addr,
) -> Result<Response, ContractError> {
    if amount.is_empty() {
        return Err(ContractError::NoFunds {});
    }
    // ensure the requested channel is registered
    if !CHANNEL_INFO.has(deps.storage, &msg.channel) {
        return Err(ContractError::NoSuchChannel { id: msg.channel });
    }

    // delta from user is in seconds
    let timeout_delta = match msg.timeout {
        Some(t) => t,
        None => CONFIG.load(deps.storage)?.default_timeout,
    };
    // timeout is in nanoseconds
    let timeout = env.block.time.plus_seconds(timeout_delta);

    // build ics20 packet
    let packet = Ics20Packet::new(
        amount.amount(),
        amount.denom(),
        sender.as_ref(),
        &msg.remote_address,
    );
    packet.validate()?;

    // prepare message
    let msg = IbcMsg::SendPacket {
        channel_id: msg.channel,
        data: to_binary(&packet)?,
        timeout: timeout.into(),
    };

    // Note: we update local state when we get ack - do not count this transfer towards anything until acked
    // similar event messages like ibctransfer module

    // send response
    let res = Response::new()
        .add_message(msg)
        .add_attribute("action", "transfer")
        .add_attribute("sender", &packet.sender)
        .add_attribute("receiver", &packet.receiver)
        .add_attribute("denom", &packet.denom)
        .add_attribute("amount", &packet.amount.to_string());
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let version = get_contract_version(deps.storage)?;
    if version.contract != CONTRACT_NAME {
        return Err(ContractError::CannotMigrate {
            previous_contract: version.contract,
        });
    }
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Admin {} => to_binary(&query_admin(deps)?),
        QueryMsg::HasContract { address } => to_binary(&query_has_contract(deps, address)?),
        QueryMsg::AllContracts { start_after, limit } => {
            to_binary(&query_all_contracts(deps, start_after, limit)?)
        }
        QueryMsg::Port {} => to_binary(&query_port(deps)?),
        QueryMsg::ListChannels {} => to_binary(&query_list(deps)?),
        QueryMsg::Channel { id } => to_binary(&query_channel(deps, id)?),
    }
}

fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(AdminResponse {
        admin: config.admin,
    })
}

fn query_has_contract(deps: Deps, address: String) -> StdResult<HasContractResponse> {
    let cw20_addr = deps.api.addr_validate(&address)?;
    let registered = CONTRACTS_INFO.has(deps.storage, &cw20_addr);
    Ok(HasContractResponse { registered })
}

pub fn query_all_contracts(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<AllContractsResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    let contracts = CONTRACTS_INFO
        .keys(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(Into::into))
        .collect::<StdResult<_>>()?;

    Ok(AllContractsResponse { contracts })
}

fn query_port(deps: Deps) -> StdResult<PortResponse> {
    let query = IbcQuery::PortId {}.into();
    let PortIdResponse { port_id } = deps.querier.query(&query)?;
    Ok(PortResponse { port_id })
}

fn query_list(deps: Deps) -> StdResult<ListChannelsResponse> {
    let channels = CHANNEL_INFO
        .range_raw(deps.storage, None, None, Order::Ascending)
        .map(|r| r.map(|(_, v)| v))
        .collect::<StdResult<_>>()?;
    Ok(ListChannelsResponse { channels })
}

// make public for ibc tests
pub fn query_channel(deps: Deps, id: String) -> StdResult<ChannelResponse> {
    let info = CHANNEL_INFO.load(deps.storage, &id)?;
    // this returns Vec<(outstanding, total)>
    let state = CHANNEL_STATE
        .prefix(&id)
        .range(deps.storage, None, None, Order::Ascending)
        .map(|r| {
            r.map(|(denom, v)| {
                let outstanding = Amount::from_parts(denom.clone(), v.outstanding);
                let total = Amount::from_parts(denom, v.total_sent);
                (outstanding, total)
            })
        })
        .collect::<StdResult<Vec<_>>>()?;
    // we want (Vec<outstanding>, Vec<total>)
    let (balances, total_sent) = state.into_iter().unzip();

    Ok(ChannelResponse {
        info,
        balances,
        total_sent,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helpers::*;

    use cosmwasm_std::testing::{mock_env, mock_info};
    use cosmwasm_std::{coin, coins, CosmosMsg, IbcMsg, StdError, Uint128};

    use cw_utils::PaymentError;

    #[test]
    fn setup_and_query() {
        let deps = setup(&["channel-3", "channel-7"]);

        let raw_list = query(deps.as_ref(), mock_env(), QueryMsg::ListChannels {}).unwrap();
        let list_res: ListChannelsResponse = from_binary(&raw_list).unwrap();
        assert_eq!(2, list_res.channels.len());
        assert_eq!(mock_channel_info("channel-3"), list_res.channels[0]);
        assert_eq!(mock_channel_info("channel-7"), list_res.channels[1]);

        let raw_channel = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Channel {
                id: "channel-3".to_string(),
            },
        )
        .unwrap();
        let chan_res: ChannelResponse = from_binary(&raw_channel).unwrap();
        assert_eq!(chan_res.info, mock_channel_info("channel-3"));
        assert_eq!(0, chan_res.total_sent.len());
        assert_eq!(0, chan_res.balances.len());

        let err = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Channel {
                id: "channel-10".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(err, StdError::not_found("cw20_ics20::state::ChannelInfo"));
    }

    #[test]
    fn proper_checks_on_execute_native() {
        let send_channel = "channel-5";
        let mut deps = setup(&[send_channel, "channel-10"]);

        let mut transfer = TransferMsg {
            channel: send_channel.to_string(),
            remote_address: "foreign-address".to_string(),
            timeout: None,
        };

        // works with proper funds
        let msg = ExecuteMsg::Transfer(transfer.clone());
        let info = mock_info("foobar", &coins(1234567, "ucosm"));
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        if let CosmosMsg::Ibc(IbcMsg::SendPacket {
            channel_id,
            data,
            timeout,
        }) = &res.messages[0].msg
        {
            let expected_timeout = mock_env().block.time.plus_seconds(DEFAULT_TIMEOUT);
            assert_eq!(timeout, &expected_timeout.into());
            assert_eq!(channel_id.as_str(), send_channel);
            let msg: Ics20Packet = from_binary(data).unwrap();
            assert_eq!(msg.amount, Uint128::new(1234567));
            assert_eq!(msg.denom.as_str(), "ucosm");
            assert_eq!(msg.sender.as_str(), "foobar");
            assert_eq!(msg.receiver.as_str(), "foreign-address");
        } else {
            panic!("Unexpected return message: {:?}", res.messages[0]);
        }

        // reject with no funds
        let msg = ExecuteMsg::Transfer(transfer.clone());
        let info = mock_info("foobar", &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::Payment(PaymentError::NoFunds {}));

        // reject with multiple tokens funds
        let msg = ExecuteMsg::Transfer(transfer.clone());
        let info = mock_info("foobar", &[coin(1234567, "ucosm"), coin(54321, "uatom")]);
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::Payment(PaymentError::MultipleDenoms {}));

        // reject with bad channel id
        transfer.channel = "channel-45".to_string();
        let msg = ExecuteMsg::Transfer(transfer);
        let info = mock_info("foobar", &coins(1234567, "ucosm"));
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::NoSuchChannel {
                id: "channel-45".to_string()
            }
        );
    }

    #[test]
    fn update_admin() {
        let mut deps = setup(&["channel-3", "channel-7"]);

        let info = mock_info("anyone2", &[]);
        let err = execute_update_admin(deps.as_mut(), info, None).unwrap_err();
        assert_eq!(err, ContractError::NotAdmin {});

        let info = mock_info("anyone", &[]);
        let res = execute_update_admin(deps.as_mut(), info, None).unwrap();
        assert_eq!(0, res.messages.len());

        let info = mock_info("anyone", &[]);
        let err = execute_update_admin(deps.as_mut(), info, None).unwrap_err();
        assert_eq!(err, ContractError::NotAdmin {});

        let data = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let res: AdminResponse = from_binary(&data).unwrap();
        assert_eq!("None", res.admin);
    }

    #[test]
    fn register_cw20() {
        let mut deps = setup(&["channel-3", "channel-7"]);
        let cw20_addr = "my-token".to_string();
        let info = mock_info("anyone2", &[]);
        let err =
            execute_register_cw20(deps.as_mut(), info, cw20_addr.clone(), "denom".to_string())
                .unwrap_err();
        assert_eq!(err, ContractError::NotAdmin {});

        let info = mock_info("anyone", &[]);
        let res =
            execute_register_cw20(deps.as_mut(), info, cw20_addr.clone(), "denom".to_string())
                .unwrap();
        assert_eq!(0, res.messages.len());

        let data = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::HasContract {
                address: cw20_addr.clone(),
            },
        )
        .unwrap();
        let res: HasContractResponse = from_binary(&data).unwrap();
        assert_eq!(true, res.registered);

        let data = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllContracts {
                start_after: None,
                limit: Some(10),
            },
        )
        .unwrap();
        let res: AllContractsResponse = from_binary(&data).unwrap();
        assert_eq!(1, res.contracts.len());
        assert_eq!(cw20_addr, res.contracts[0]);
    }

    #[test]
    fn proper_checks_on_execute_cw20() {
        let send_channel = "channel-15";
        let mut deps = setup(&["channel-3", send_channel]);

        let cw20_addr = "my-token";
        let transfer = TransferMsg {
            channel: send_channel.to_string(),
            remote_address: "foreign-address".to_string(),
            timeout: Some(7777),
        };
        let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: "my-account".into(),
            amount: Uint128::new(888777666),
            msg: to_binary(&transfer).unwrap(),
        });

        // contract no registered
        let info = mock_info(cw20_addr, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap_err();
        assert_eq!(
            err,
            ContractError::NoContractAllowed {
                contract: cw20_addr.to_string()
            }
        );

        // register cw20
        execute_register_cw20(
            deps.as_mut(),
            mock_info("anyone", &[]),
            cw20_addr.to_string(),
            "denom".to_string(),
        )
        .unwrap();
        // works with proper funds
        let info = mock_info(cw20_addr, &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();
        assert_eq!(1, res.messages.len());
        if let CosmosMsg::Ibc(IbcMsg::SendPacket {
            channel_id,
            data,
            timeout,
        }) = &res.messages[0].msg
        {
            let expected_timeout = mock_env().block.time.plus_seconds(7777);
            assert_eq!(timeout, &expected_timeout.into());
            assert_eq!(channel_id.as_str(), send_channel);
            let msg: Ics20Packet = from_binary(data).unwrap();
            assert_eq!(msg.amount, Uint128::new(888777666));
            assert_eq!(msg.denom, format!("cw20:{}:denom", cw20_addr));
            assert_eq!(msg.sender.as_str(), "my-account");
            assert_eq!(msg.receiver.as_str(), "foreign-address");
        } else {
            panic!("Unexpected return message: {:?}", res.messages[0]);
        }

        // reject with tokens funds
        let info = mock_info("foobar", &coins(1234567, "ucosm"));
        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        assert_eq!(err, ContractError::Payment(PaymentError::NonPayable {}));
    }
}
