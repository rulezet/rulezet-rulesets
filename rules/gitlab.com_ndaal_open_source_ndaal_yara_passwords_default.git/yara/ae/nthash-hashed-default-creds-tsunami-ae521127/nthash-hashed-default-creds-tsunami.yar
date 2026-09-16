rule nthash_hashed_default_creds_tsunami
{
    meta:
        id = "2vbiI33mE8km2XgemBZSyl"
        fingerprint = "2c693281514db3f2349a8168fb446e99de6d9b7615ee5f5d5562610eca088ccb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54b5028cc3062efa2570258decd2d27f"
    $a1="54b5028cc3062efa2570258decd2d27f"
condition:
    ($a0 and $a1)
}