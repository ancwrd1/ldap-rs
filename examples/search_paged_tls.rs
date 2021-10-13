use ldap_rs::{
    controls::SimplePagedResultsControl,
    rasn_ldap::{SearchRequestDerefAliases, SearchRequestScope},
    request::SearchRequestBuilder,
    LdapClient, TlsOptions,
};

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

    let size = 1;
    let mut ctrl = SimplePagedResultsControl::new(size);
    loop {
        let result = client
            .search_paged(req.clone(), ctrl.with_size(size))
            .await
            .unwrap();
        ctrl = result.1;
        println!(
            "Page cookie: {}, returned size: {}",
            !ctrl.cookie().is_empty(),
            ctrl.size()
        );
        println!("{:#?}", result.0);

        if ctrl.cookie().is_empty() {
            break;
        }
    }
}
