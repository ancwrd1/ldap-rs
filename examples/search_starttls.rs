use futures::TryStreamExt;

use ldap_rs::{LdapClient, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, TlsOptions};

#[tokio::main]
async fn main() {
    let mut client = LdapClient::builder("ldap.forumsys.com")
        .tls_options(TlsOptions::starttls().verify_certs(false))
        .connect()
        .await
        .unwrap();
    client
        .simple_bind("cn=read-only-admin,dc=example,dc=com", "password")
        .await
        .unwrap();

    let req = SearchRequest::builder()
        .base_dn("dc=example,dc=com")
        .scope(SearchRequestScope::WholeSubtree)
        .deref_aliases(SearchRequestDerefAliases::NeverDerefAliases)
        .filter("(&(objectClass=person)(uid=ne*t*n))")
        .build()
        .unwrap();

    let result = client.search(req).await.unwrap();
    let items = result.try_collect::<Vec<_>>().await.unwrap();
    println!("{:#?}", items);
}
