rule nthash_hashed_default_creds_avocent
{
    meta:
        id = "6KtwAZgbqFDu31GwSeKgRR"
        fingerprint = "988717935d8fd42d83bfdd44d280d622ec9c8ff0059f094093cac707e0940f47"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for avocent."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a94c9db11b77462c8956d761b4a92baf"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}