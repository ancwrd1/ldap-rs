use ldap_rs::LdapClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = LdapClient::builder("ldap.forumsys.com").connect().await.unwrap();
    client
        .simple_bind("cn=read-only-admin,dc=example,dc=com", "password")
        .await?;
    println!("Bind succeeded!");

    client.unbind().await?;
    println!("Unbind succeeded!");

    Ok(())
}
