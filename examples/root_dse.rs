use futures::TryStreamExt;

use ldap_rs::{LdapClient, SearchRequest};

#[tokio::main]
async fn main() {
    let mut client = LdapClient::builder("ldap.forumsys.com").connect().await.unwrap();

    let req = SearchRequest::root_dse();

    let result = client.search(req).await.unwrap();
    let items = result.try_collect::<Vec<_>>().await.unwrap();
    println!("{:#?}", items);
}
