rule sha1_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="268c47f843d93c58480f67e84c54d0755303f64e"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="19245a47f73a1bdbb59babc52d8266fc75d7c7be"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="816c52fd2bdd94a63cd0944823a6c0aa9384c103"
    $a5="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}