use ldap_rs::{Attribute, LdapClient, ModifyRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    let mut client = LdapClient::builder("ad-dc.intranet.lan").connect().await?;
    client.simple_bind("admin@intranet.lan", "password").await?;

    let attr = Attribute {
        name: "mobile".to_owned(),
        values: vec![b"123456".to_vec().into()],
    };
    let req = ModifyRequest::builder("cn=myuser,cn=Users,dc=intranet,dc=lan")
        .replace(attr)
        .build();

    client.modify(req).await?;

    Ok(())
}
