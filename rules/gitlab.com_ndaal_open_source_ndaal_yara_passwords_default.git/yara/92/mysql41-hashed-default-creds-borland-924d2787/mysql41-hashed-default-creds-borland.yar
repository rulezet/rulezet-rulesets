rule mysql41_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5A5B36727E0D98B09E6500A114D733774A49B2CC"
    $a1="*0F8480A9AA9FEDC3612024057AC37A9B80B69B9D"
    $a2="*5A5B36727E0D98B09E6500A114D733774A49B2CC"
    $a3="*84A747E1D08F0AFA1065D999F283522B1025DC2F"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}