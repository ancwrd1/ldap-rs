use ldap_rs::LdapClient;

#[tokio::main]
async fn main() {
    let mut client = LdapClient::builder("ldap.forumsys.com").connect().await.unwrap();
    client
        .simple_bind("cn=read-only-admin,dc=example,dc=com", "password")
        .await
        .unwrap();
    client.unbind().await.unwrap();
}
