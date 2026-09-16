rule sha256_hashed_default_creds_prtg
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for prtg."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7e3acd1d0553393aaf82d4a893422ced3cee013fded53491a1763c898d37682"
    $a1="a7e3acd1d0553393aaf82d4a893422ced3cee013fded53491a1763c898d37682"
condition:
    ($a0 and $a1)
}