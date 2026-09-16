rule mysql41_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*9AFCD0A8A29FECE3F407225BABC42CA3F98D4E6A"
    $a1="*9AFCD0A8A29FECE3F407225BABC42CA3F98D4E6A"
    $a2="*6566952868A994DDB4138ACB295F0CFA73B37E4B"
    $a3="*D4647DEFCB590293FD916EC3B35B7BC793E6A599"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}