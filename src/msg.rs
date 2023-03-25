use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Coin};
use cw_utils::Expiration;

#[cw_serde]
//We're creating the contract 
//This is come from the user
pub struct InstantiateMsg {
    pub arbiter: String,        //we use invalidated String address which should be validated by contract
    pub recipient: String,
    /// When end height set and block height exceeds this value, the escrow is expired.
    /// Once an escrow is expired, it can be returned to the original funder (via "refund").
    ///
    /// When end time (in seconds since epoch 00:00:00 UTC on 1 January 1970) is set and
    /// block time exceeds this value, the escrow is expired.
    /// Once an escrow is expired, it can be returned to the original funder (via "refund").
    pub expiration: Option<Expiration>,     //this is optional, it can be Some or None
}

#[cw_serde]
//We're using the contract 
//This come from an execute contract 
pub enum ExecuteMsg {
    Approve {
        // release some coins - if quantity is None, release all coins in balance
        quantity: Option<Vec<Coin>>,
    },
    Refund {},
     
    Steal { //We wanted to add an steal funciton to our contract
        destination: String, //this will be an address
    
        
    },
}
//we're quering the contract for data 
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns a human-readable representation of the arbiter.
    #[returns(ArbiterResponse)]
    Arbiter {},
}

#[cw_serde]
pub struct ArbiterResponse {
    pub arbiter: Addr,
}
