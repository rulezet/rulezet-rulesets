rule nthash_hashed_default_creds_aztech
{
    meta:
        id = "4XWmvUTtUXrNUwIJpSCi3A"
        fingerprint = "5da8caf45e4519ce8c0f30a10c91acfd6cca4f625a55d550978a06318379c868"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aztech."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="659a32a8cc56a2d3b1ae5f2026473c5d"
    $a3="659a32a8cc56a2d3b1ae5f2026473c5d"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}