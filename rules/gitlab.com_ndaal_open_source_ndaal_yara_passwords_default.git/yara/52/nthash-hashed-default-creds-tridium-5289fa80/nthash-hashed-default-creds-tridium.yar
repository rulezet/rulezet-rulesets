rule nthash_hashed_default_creds_tridium
{
    meta:
        id = "eKLerShLYCLTYuHSXJJDW"
        fingerprint = "f010f3f476e0a17f5bf2a87dab7491213913efe0aad6826e2c9dd52c9606141f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26f088662b9ff69fd6d83b5a87c9d885"
    $a1="438100f2c044bd1e7a1eedfdc2bc1769"
condition:
    ($a0 and $a1)
}