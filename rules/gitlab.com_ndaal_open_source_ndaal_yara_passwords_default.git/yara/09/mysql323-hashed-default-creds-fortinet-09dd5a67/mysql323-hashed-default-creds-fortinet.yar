rule mysql323_hashed_default_creds_fortinet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="0ac87996221cd58b"
    $a2="30e7329b44263334"
    $a3="0ac87996221cd58b"
    $a4="22ab72a84e3f6eeb"
    $a5="0ac87996221cd58b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}