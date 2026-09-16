rule nthash_hashed_default_creds_applied_innovations
{
    meta:
        id = "j5W4vVTytpJt15pTHFqW"
        fingerprint = "9367a414b172e74f87fa1f62c15e980780bb98567c4906fb5af78611e4165a46"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0be8cbd164f59a1ebb68d8df9da49343"
    $a1="0be8cbd164f59a1ebb68d8df9da49343"
condition:
    ($a0 and $a1)
}