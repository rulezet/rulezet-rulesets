rule nthash_hashed_default_creds_sonus
{
    meta:
        id = "5ukmVhLqXrXGaDKhxIFw0j"
        fingerprint = "53c6d6f60133fd0460cd4c7ee14df1ce7299f623a1059e66b167ce4792c4698e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sonus."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e000d00aaaa09a0d90af2e5988a2819"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="454c5b536a9cb7120eadb52878d63a26"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}