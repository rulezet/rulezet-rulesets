rule sha384_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
    $a1="9983ad0b945fd130fc105233ca24fd32bbf936eb5196baa6c74454d7e4225fc7225a7fbffb8d5a7170648af34b171a53"
condition:
    ($a0 and $a1)
}