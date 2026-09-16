rule sha224_hashed_default_creds_elasticsearch_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for elasticsearch_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a1="684fe53dec11ca6e8b075e1ec0a9b55c0d246b2d6bdee35b00340e78"
condition:
    ($a0 and $a1)
}