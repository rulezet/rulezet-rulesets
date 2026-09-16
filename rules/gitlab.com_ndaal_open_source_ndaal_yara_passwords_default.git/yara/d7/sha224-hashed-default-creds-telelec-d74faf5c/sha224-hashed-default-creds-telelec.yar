rule sha224_hashed_default_creds_telelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telelec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d19b187a2c44a9043d2941a96f588a644098c7a06381855aac2bce1e"
    $a1="d19b187a2c44a9043d2941a96f588a644098c7a06381855aac2bce1e"
condition:
    ($a0 and $a1)
}