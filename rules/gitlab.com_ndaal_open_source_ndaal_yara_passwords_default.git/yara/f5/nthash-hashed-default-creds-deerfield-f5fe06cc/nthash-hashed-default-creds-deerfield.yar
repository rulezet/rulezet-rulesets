rule nthash_hashed_default_creds_deerfield
{
    meta:
        id = "17nYnChq9sIrOf3diSKx7F"
        fingerprint = "31f3537f03578fc11b79e8ab987b78ae61fbe8dff3fd8769d78c3adb5af8ab1f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="218ac6d99e55eddd5f62c1d2ede91569"
    $a1="c25c6ec51b15bc7c611faf8f0f7424e4"
condition:
    ($a0 and $a1)
}