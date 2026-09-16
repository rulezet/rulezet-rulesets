rule sha3_256_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
    $a1="5c96d4251251492e3f5a17cd90cea0224932e4851321a2264abbad37683dbd2e"
condition:
    ($a0 and $a1)
}