rule nthash_hashed_default_creds_patton
{
    meta:
        id = "BKFDpLBaL3zGFjqGCdula"
        fingerprint = "636dc6338b31e35faf937bc66d2b1cc2d1f7b247965e8f82a7cba2fde0be902a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b6be948d1d1b370bdefe5d6c74142a6"
    $a1="3b6be948d1d1b370bdefe5d6c74142a6"
    $a2="8f62e69c0919247c923b60a23c0e46b4"
    $a3="8f62e69c0919247c923b60a23c0e46b4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}