rule sha224_hashed_default_creds_lgic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lgic."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="839f9f9fb767e4b37067b4a6da6b95fc85cf8a1d9f3b61eb66e31e55"
    $a1="839f9f9fb767e4b37067b4a6da6b95fc85cf8a1d9f3b61eb66e31e55"
condition:
    ($a0 and $a1)
}