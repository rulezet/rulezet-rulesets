rule nthash_hashed_default_creds_aztecj
{
    meta:
        id = "4cwviitjT4c7qomi2QdRhG"
        fingerprint = "d26e018cb5b17edc47f3e4b4ce3d66f14dd87873f0faf0d407ceadd5b5246aaa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aztecj."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="659a32a8cc56a2d3b1ae5f2026473c5d"
    $a1="659a32a8cc56a2d3b1ae5f2026473c5d"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}