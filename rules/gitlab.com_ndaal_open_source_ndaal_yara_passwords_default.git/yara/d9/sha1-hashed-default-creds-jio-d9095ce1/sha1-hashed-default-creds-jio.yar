rule sha1_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d7cc4f46a389d1c09a429ecfc2dd5c54687d973"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a3="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}