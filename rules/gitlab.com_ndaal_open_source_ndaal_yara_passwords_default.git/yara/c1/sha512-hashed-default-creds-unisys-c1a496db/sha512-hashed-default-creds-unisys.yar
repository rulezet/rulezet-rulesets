rule sha512_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22500de59d4c497fb66ef2fd70f31f8e64e37afe4bdd05d92650fc9464d852dfd0755783085ed762c474dc11ec35ce7df1ce8beb5767d3769a50ff5b6a88c5ba"
    $a1="22500de59d4c497fb66ef2fd70f31f8e64e37afe4bdd05d92650fc9464d852dfd0755783085ed762c474dc11ec35ce7df1ce8beb5767d3769a50ff5b6a88c5ba"
    $a2="81b64845be8c00c4092674cf00f085561fae4d9ab6c16f7bf48f0f1f4dd108db5d869ec2ef0a1e6c120ca2c7c33dccc41b4e542abf9e5c2cd24c9f517172151c"
    $a3="81b64845be8c00c4092674cf00f085561fae4d9ab6c16f7bf48f0f1f4dd108db5d869ec2ef0a1e6c120ca2c7c33dccc41b4e542abf9e5c2cd24c9f517172151c"
    $a4="7eadc0558bb685b60c9838275fe9ff9c4ef6e8945428b446f15f305fca7ab6d5308ece5bfcac25369aa0c98778b8d0d4b6e495a4ddf3dc42488060fb00c893d8"
    $a5="7eadc0558bb685b60c9838275fe9ff9c4ef6e8945428b446f15f305fca7ab6d5308ece5bfcac25369aa0c98778b8d0d4b6e495a4ddf3dc42488060fb00c893d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}