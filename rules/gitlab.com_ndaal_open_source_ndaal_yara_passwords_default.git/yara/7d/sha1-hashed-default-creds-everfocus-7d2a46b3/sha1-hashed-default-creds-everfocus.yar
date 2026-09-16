rule sha1_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="fe96dd39756ac41b74283a9292652d366d73931f"
    $a3="fe96dd39756ac41b74283a9292652d366d73931f"
    $a4="0f4d09e43d208d5e9222322fbc7091ceea1a78c3"
    $a5="0f4d09e43d208d5e9222322fbc7091ceea1a78c3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}