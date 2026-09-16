rule blake2s_hashed_default_creds_tekelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6f8839ae82b7e03ad2588043c694b6c7edcc39b7ea68916c2371d3ae3494ec75"
    $a1="6f8839ae82b7e03ad2588043c694b6c7edcc39b7ea68916c2371d3ae3494ec75"
condition:
    ($a0 and $a1)
}