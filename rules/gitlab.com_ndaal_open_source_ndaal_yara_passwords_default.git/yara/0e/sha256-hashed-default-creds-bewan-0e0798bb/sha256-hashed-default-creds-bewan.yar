rule sha256_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99244ee9c3ca6d758485858bdfeb5c5bf3f6d786e4c2fb78f57ebf21ad6c53c1"
    $a1="99244ee9c3ca6d758485858bdfeb5c5bf3f6d786e4c2fb78f57ebf21ad6c53c1"
condition:
    ($a0 and $a1)
}