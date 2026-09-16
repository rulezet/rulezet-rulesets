rule sha256_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
    $a1="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
condition:
    ($a0 and $a1)
}