rule sha224_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c633405fd3b19f174038f555b4c61c8e0f17e839257d67dd4916bbb"
    $a1="14cfe7c06767d8a8a8f8dacd595d684dc60c4bed76cdb89a80c1eb29"
condition:
    ($a0 and $a1)
}