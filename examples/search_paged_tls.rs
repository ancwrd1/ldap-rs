use futures::{StreamExt, TryStreamExt};

use ldap_rs::{LdapClient, SearchRequest, SearchRequestDerefAliases, SearchRequestScope, TlsOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    let mut client = LdapClient::builder("myldap.intranet.lan")
        .port(636)
        .tls_options(TlsOptions::tls())
        .connect()
        .await?;
    client.simple_bind("dmitry@intranet.lan", "notverysecure").await?;

    // Active Directory search example
    let req = SearchRequest::builder()
        .base_dn("dc=intranet,dc=lan")
        .scope(SearchRequestScope::WholeSubtree)
        .deref_aliases(SearchRequestDerefAliases::NeverDerefAliases)
        .filter("(&(objectClass=person)(cn=*dm*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
        .build()?;

    let mut page_stream = client.search_paged(req, 1);

    while let Some(page) = page_stream.next().await {
        let items = page?.try_collect::<Vec<_>>().await?;
        println!("Next page: {items:#?}");
    }
    Ok(())
}
