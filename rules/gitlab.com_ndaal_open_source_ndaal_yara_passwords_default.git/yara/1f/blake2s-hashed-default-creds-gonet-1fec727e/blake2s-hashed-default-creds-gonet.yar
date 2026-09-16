rule blake2s_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26a6fd7063309f44cfa64b4752d5f84ab116c1e296db1c93b462c5be933d465a"
    $a1="fb3e4d0cc8bcdcd2ba9fe50ca1d80ec6972557182d4bcbe20c63ac8394947967"
condition:
    ($a0 and $a1)
}