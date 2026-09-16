rule mysql323_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="515b87cb3f4ff43c"
    $a1="4829c53d6f9319a1"
    $a2="37bd7c4221e8a247"
    $a3="37bd7c4221e8a247"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}