rule mysql323_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="45677c2b2cfa0386"
    $a1="43e9a4ab75570f5b"
    $a2="0098f168041e3162"
    $a3="13a2a1682efa52e3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}