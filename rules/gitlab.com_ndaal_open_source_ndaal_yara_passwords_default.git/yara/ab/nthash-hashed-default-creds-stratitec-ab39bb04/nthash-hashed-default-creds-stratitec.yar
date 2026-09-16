rule nthash_hashed_default_creds_stratitec
{
    meta:
        id = "AiDjmbzhTOrJpxX5rZCok"
        fingerprint = "9fcdccf10a8d83eebfaeb27b0b99a7c2c6a6870e49cef6f517a6dc630dc2729c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratitec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10b47b31cbb0cd8d6b98f0a75f724b29"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}