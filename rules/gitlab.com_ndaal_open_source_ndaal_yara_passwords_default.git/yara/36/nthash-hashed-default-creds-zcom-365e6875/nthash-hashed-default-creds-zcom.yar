rule nthash_hashed_default_creds_zcom
{
    meta:
        id = "5QwndvUccShsJxtvgZ7mrc"
        fingerprint = "3610e3e9c444a75ab4b50c0ef71fda3cd136b6098ad21eb2a08be44241387124"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zcom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}