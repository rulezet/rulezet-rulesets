rule nthash_hashed_default_creds_efficient
{
    meta:
        id = "7QGn2Prma3xCMRY1MG1wLM"
        fingerprint = "dee5b3d5c451da14a5c1ea935cacf745d17a914848cb4f4c1d5a0e0997ea8513"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="e6bd4cdb1e447131b60418f31d0b81d6"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="e6bd4cdb1e447131b60418f31d0b81d6"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="8f62e69c0919247c923b60a23c0e46b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}