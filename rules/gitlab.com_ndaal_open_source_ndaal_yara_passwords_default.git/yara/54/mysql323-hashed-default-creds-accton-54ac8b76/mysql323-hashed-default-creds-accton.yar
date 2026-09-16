rule mysql323_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5336eb751494bdb1"
    $a1="5336eb751494bdb1"
    $a2="62068042172418e8"
    $a3="62068042172418e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}