rule sha224_hashed_default_creds_general_instruments
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_instruments."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
    $a1="90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
condition:
    ($a0 and $a1)
}