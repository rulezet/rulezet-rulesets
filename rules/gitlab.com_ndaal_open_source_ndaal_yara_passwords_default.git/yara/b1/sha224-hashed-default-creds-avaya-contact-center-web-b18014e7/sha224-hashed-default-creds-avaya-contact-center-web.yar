rule sha224_hashed_default_creds_avaya_contact_center_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avaya_contact_center_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
    $a1="22d417dcf61fea58e9cdc85ce70382c7bf7d5553bc9f0774a3287b7b"
condition:
    ($a0 and $a1)
}