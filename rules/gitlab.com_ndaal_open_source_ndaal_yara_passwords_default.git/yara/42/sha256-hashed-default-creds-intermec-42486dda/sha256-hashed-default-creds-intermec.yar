rule sha256_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
    $a1="c8d410cf1342a13c16a52206fc720a46b48c07d14b15a584f5e4927dbca04896"
condition:
    ($a0 and $a1)
}