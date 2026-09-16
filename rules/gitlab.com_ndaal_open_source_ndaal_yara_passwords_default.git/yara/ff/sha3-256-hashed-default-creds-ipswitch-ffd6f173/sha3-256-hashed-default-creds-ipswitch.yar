rule sha3_256_hashed_default_creds_ipswitch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ipswitch."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="639fe8cfb0d379f696dd2f50b5ab56ec74f404b3a67708f5ee6c4b5c36706489"
    $a3="4281bf3d0900eb791393ddd9f8084437463d2634ef14db94f5f9a33f1fd61b2f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}