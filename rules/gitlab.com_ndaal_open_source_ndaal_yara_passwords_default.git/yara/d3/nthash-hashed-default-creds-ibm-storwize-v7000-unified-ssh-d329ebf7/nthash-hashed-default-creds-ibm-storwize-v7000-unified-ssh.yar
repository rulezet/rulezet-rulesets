rule nthash_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        id = "2uZ3SK9VsinTwqerqEXEVR"
        fingerprint = "a9fd0638544fc50f4241cc4f7cf6540069a267b0b58f88b24ed96a40eeab6d70"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a64773b37e9751de3083ac6accdbf69f"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a87f3a337d73085c45f9416be5787d86"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="b9f917853e3dbf6e6831ecce60725930"
    $a5="8f62e69c0919247c923b60a23c0e46b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}