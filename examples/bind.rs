use ldap_rs::LdapClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    let mut client = LdapClient::builder("ldap.forumsys.com").connect().await.unwrap();
    client
        .simple_bind("cn=read-only-admin,dc=example,dc=com", "password")
        .await?;
    println!("Bind succeeded!");

    let authz = client.whoami().await?;
    println!("Authz: {:?}", authz);

    client.unbind().await?;
    println!("Unbind succeeded!");

    println!("{:?}", client.whoami().await);

    Ok(())
}
