rule sha3_256_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
    $a1="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
    $a2="424eadc41c02be1e3b82f976fd9294a62f29d0536a75869bd40e212a3409b9f3"
    $a3="ba1a564a4a50e0cb98951923e3b0c1fa6fba2841eddc4984f6dde5d8ee2de0d8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}