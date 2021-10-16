use futures::{StreamExt, TryStreamExt};

use ldap_rs::{LdapClient, SearchRequestBuilder, SearchRequestDerefAliases, SearchRequestScope, TlsOptions};

#[tokio::main]
async fn main() {
    let mut client = LdapClient::builder("myldap.intranet.lan")
        .port(636)
        .tls_options(TlsOptions::tls())
        .build_and_connect()
        .await
        .unwrap();
    client
        .simple_bind("dmitry@intranet.lan", "notverysecure")
        .await
        .unwrap();

    // example how to search users which are not disabled in the Active Directory using rule filters
    let req = SearchRequestBuilder::new()
        .base_dn("dc=intranet,dc=lan")
        .scope(SearchRequestScope::WholeSubtree)
        .deref_aliases(SearchRequestDerefAliases::NeverDerefAliases)
        .filter("(&(objectClass=person)(cn=*dm*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
        .build()
        .unwrap();

    let mut page_stream = client.search_paged(req, 1);

    while let Some(Ok(page)) = page_stream.next().await {
        let items = page.try_collect::<Vec<_>>().await.unwrap();
        println!("{:#?}", items);
    }
}
