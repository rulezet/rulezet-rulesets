rule sha256_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37c0b2244593c32dbda695aacd552918c77bc63f0dc8b9513cf357fcc7b4ac6d"
    $a1="37c0b2244593c32dbda695aacd552918c77bc63f0dc8b9513cf357fcc7b4ac6d"
condition:
    ($a0 and $a1)
}