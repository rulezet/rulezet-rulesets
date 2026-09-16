rule nthash_hashed_default_creds_intershop
{
    meta:
        id = "5T8QBAewSWx1zjEtkoRM2f"
        fingerprint = "3c02be56e8e23c990672d251d5153adea2fc083e84300f1d4da1f0b1ac74a701"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intershop."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5bbfb92827c8d867156ed0f48c80ee5a"
    $a1="e337e31aa4c614b2895ad684a51156df"
condition:
    ($a0 and $a1)
}