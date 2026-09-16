rule sha256_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f6ae74f84b4213f16f22dbf21423cb7b9af26e881109b65f83b2903a391b39d6"
    $a1="24c30216b298744ccc2ba61ab433b71143d2838d4d8ed8bccdbe606cc76ee8e5"
condition:
    ($a0 and $a1)
}