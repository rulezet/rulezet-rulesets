rule nthash_hashed_default_creds_moxa
{
    meta:
        id = "1pUz8LDn1bSIbYG8kAENEf"
        fingerprint = "423c83f3768919ccf35b79b754b9e7f8ed542c7dfd32e481bf5acfdf0cd32807"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for moxa."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329153f560eb329c0e1deea55e88a1e9"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="329153f560eb329c0e1deea55e88a1e9"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}