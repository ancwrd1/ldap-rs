use futures::TryStreamExt;
use ldap_rs::{LdapClient, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, TlsOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    #[cfg(feature = "tls-native-tls")]
    let options = {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        TlsOptions::start_tls().tls_connector(connector)
    };

    #[cfg(not(feature = "tls-native-tls"))]
    let options = TlsOptions::start_tls();

    let mut client = LdapClient::builder("ldap.forumsys.com")
        .tls_options(options)
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
    println!("Items: {items:#?}");

    Ok(())
}
