use futures::TryStreamExt;

use ldap_rs::{LdapClient, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, TlsOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    let mut client = LdapClient::builder("ldap.forumsys.com")
        .tls_options(TlsOptions::start_tls().verify_certs(false))
        .connect()
        .await?;
    client
        .simple_bind("cn=read-only-admin,dc=example,dc=com", "password")
        .await?;

    let req = SearchRequest::builder()
        .base_dn("dc=example,dc=com")
        .scope(SearchRequestScope::WholeSubtree)
        .deref_aliases(SearchRequestDerefAliases::NeverDerefAliases)
        .filter("(&(objectClass=person)(uid=ne*t*n))")
        .build()?;

    let result = client.search(req).await?;
    let items = result.try_collect::<Vec<_>>().await?;
    println!("Items: {:#?}", items);

    Ok(())
}
