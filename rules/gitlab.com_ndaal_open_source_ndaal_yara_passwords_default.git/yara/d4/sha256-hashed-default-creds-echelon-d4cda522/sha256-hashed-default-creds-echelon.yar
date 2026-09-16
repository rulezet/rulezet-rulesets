rule sha256_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
    $a1="31e50f4c66b3b08e8affd2c8c7e8de9a925372a15b0ac20c469dbc21e8dc1c01"
    $a2="a0628e2238c62a61e33789e81984de5e41ba58b85d4c7452564f2c158b3a4347"
    $a3="f2e1af85c2ff9a94981bc96e57b960e1e497f9379613311a2310e0449ee7723c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}