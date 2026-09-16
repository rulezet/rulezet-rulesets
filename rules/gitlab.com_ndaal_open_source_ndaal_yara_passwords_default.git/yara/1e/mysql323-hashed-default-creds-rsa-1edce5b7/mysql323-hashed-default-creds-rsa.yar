rule mysql323_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0c6387b11e133b6b"
    $a1="43e9a4ab75570f5b"
    $a2="68bafe0911f3f7e0"
    $a3="7a7eeba37575fe5e"
    $a4="0cf5543c07a49ac0"
    $a5="5c1fb21a20d15f82"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}