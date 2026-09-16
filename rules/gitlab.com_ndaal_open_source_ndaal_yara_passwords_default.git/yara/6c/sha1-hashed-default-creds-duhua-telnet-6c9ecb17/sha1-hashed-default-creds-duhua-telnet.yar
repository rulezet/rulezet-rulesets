rule sha1_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6401561d8326540f8d1be2112081432d8ddf62da"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="6401561d8326540f8d1be2112081432d8ddf62da"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="84e28d61e017bd7f37637e1f2581b1bcb3385cf3"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}