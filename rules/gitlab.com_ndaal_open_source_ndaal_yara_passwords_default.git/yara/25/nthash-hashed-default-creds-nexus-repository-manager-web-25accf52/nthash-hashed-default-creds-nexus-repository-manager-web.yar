rule nthash_hashed_default_creds_nexus_repository_manager_web
{
    meta:
        id = "7JBAvrMLZEx6C1ilMpmjKD"
        fingerprint = "e5a18b7dac17cee5bf94a4b8a7c7c2db6f5ee3f490aea32f4a4c8bafe9a64447"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nexus_repository_manager_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3008c87294511142799dca1191e69a0f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}