use clap::Parser;
use qsb_did_resolver_core::{
    resolver::{invalid_did_result, is_qsb_did, map_raw_to_resolution, not_found_result},
    rpc::RpcClient,
};

#[derive(Parser, Debug)]
#[command(name = "qsb-did-resolver-cli")]
#[command(about = "CLI resolver utility for did:qsb")]
struct Args {
    #[arg(
        long,
        env = "QSB_NODE_RPC_URL",
        default_value = "http://127.0.0.1:9944"
    )]
    node_rpc_url: String,
    #[arg(long, env = "QSB_RPC_TIMEOUT_SECS", default_value_t = 10)]
    rpc_timeout_secs: u64,
    #[arg(long)]
    did: String,
    #[arg(long, default_value_t = false)]
    pretty: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let rpc = RpcClient::new(args.node_rpc_url, args.rpc_timeout_secs)?;

    let result = if !is_qsb_did(&args.did) {
        invalid_did_result()
    } else {
        match rpc.did_by_string(&args.did).await? {
            Some(details) => map_raw_to_resolution(&args.did, details),
            None => not_found_result(),
        }
    };

    let output = if args.pretty {
        serde_json::to_string_pretty(&result.into_http())?
    } else {
        serde_json::to_string(&result.into_http())?
    };
    println!("{}", output);
    Ok(())
}
