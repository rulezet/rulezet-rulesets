rule sha384_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
    $a1="645104a1b9c7b10e0a1a2d11cc7030360c50eff1c9a6187d4c1318dd9a861ddad42062f1e7c980c3c0e39471e84d7499"
condition:
    ($a0 and $a1)
}