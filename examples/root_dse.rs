use futures::TryStreamExt;

use ldap_rs::{LdapClient, SearchRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    let mut client = LdapClient::builder("ldap.forumsys.com").connect().await?;

    let req = SearchRequest::root_dse();

    let result = client.search(req).await?;
    let items = result.try_collect::<Vec<_>>().await?;
    println!("Root DSE: {:#?}", items);

    Ok(())
}
