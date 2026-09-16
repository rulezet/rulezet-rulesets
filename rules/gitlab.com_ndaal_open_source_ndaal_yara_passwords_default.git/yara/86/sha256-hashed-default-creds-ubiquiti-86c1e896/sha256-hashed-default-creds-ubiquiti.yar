rule sha256_hashed_default_creds_ubiquiti
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
    $a1="1af4cfa0ae8cb48c99dec1e17e2e78e1c0dc8d84194c078537c79b2bfb1096d4"
condition:
    ($a0 and $a1)
}