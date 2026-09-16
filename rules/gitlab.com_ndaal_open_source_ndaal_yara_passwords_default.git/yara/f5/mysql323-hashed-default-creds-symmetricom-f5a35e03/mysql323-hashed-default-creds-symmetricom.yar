rule mysql323_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="264f4d756c7daf6e"
    $a1="57510426775c5b0f"
    $a2="213c762d1f8c1898"
    $a3="4297dfd67bfb01dd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}