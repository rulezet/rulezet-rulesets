rule sha3_256_hashed_default_creds_avaya_contact_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
    $a1="cae76c66f907f3a9ad797c25588a373441deb380830161fadc4b1635eb9ce438"
condition:
    ($a0 and $a1)
}