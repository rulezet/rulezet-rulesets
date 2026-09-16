rule nthash_hashed_default_creds_360_systems
{
    meta:
        id = "2UY58emnsJcj6AArtlddT5"
        fingerprint = "5867b9befdebe30ad225156ea5f16f029fd0a7356dbc0d04de3796a2c1fc3252"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3de69f85ba8907f7500e08cf8e55e33a"
    $a1="3de69f85ba8907f7500e08cf8e55e33a"
condition:
    ($a0 and $a1)
}