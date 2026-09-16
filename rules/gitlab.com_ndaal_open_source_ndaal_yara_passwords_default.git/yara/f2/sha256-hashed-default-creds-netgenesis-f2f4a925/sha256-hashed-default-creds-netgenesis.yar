rule sha256_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2afcbb35be2ea74efb2a892c88269191243b9ae605729370f0018e9526674191"
    $a1="2afcbb35be2ea74efb2a892c88269191243b9ae605729370f0018e9526674191"
condition:
    ($a0 and $a1)
}