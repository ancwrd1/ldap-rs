use futures::TryStreamExt;

use ldap_rs::{LdapClient, SearchRequestBuilder};

#[tokio::main]
async fn main() {
    let mut client = LdapClient::builder("ldap.forumsys.com")
        .build_and_connect()
        .await
        .unwrap();

    let req = SearchRequestBuilder::new().filter("(objectClass=*)").build().unwrap();

    let result = client.search(req).await.unwrap();
    let items = result.try_collect::<Vec<_>>().await.unwrap();
    println!("{:#?}", items);
}
