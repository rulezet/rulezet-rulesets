rule nthash_hashed_default_creds_various
{
    meta:
        id = "qRX5xyZnT8pVjUQ9r7sTN"
        fingerprint = "223e08d09303cf47c354a1854412cf70cb7116b7b19683e7dca29d50838cacf3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for various."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}