rule nthash_hashed_default_creds_bk_ultrasound
{
    meta:
        id = "511oQBSY4gjYd9WWlAA86y"
        fingerprint = "8e2e113d322546fcb6a5f6dfc121938caf21f5ade3d473e4d3ff996d9f20ef35"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bk_ultrasound."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f62e69c0919247c923b60a23c0e46b4"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1)
}