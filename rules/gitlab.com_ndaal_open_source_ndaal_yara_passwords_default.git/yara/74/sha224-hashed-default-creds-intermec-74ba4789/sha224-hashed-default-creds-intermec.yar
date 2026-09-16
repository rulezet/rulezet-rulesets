rule sha224_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
    $a1="557801b03af8b366efd23ed0055b05ad52757a4ae0d902b04090098c"
condition:
    ($a0 and $a1)
}