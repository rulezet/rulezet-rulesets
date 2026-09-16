rule nthash_hashed_default_creds_jaspersoft_corporation
{
    meta:
        id = "1ctzjYSObX5HlEif25D4b"
        fingerprint = "b84c0f904d690ad5a20fa6f331ea4b2f8d201ee0f804f20b0d000cea66e76553"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a1="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a2="7d12dddeaff695c2c74dc78043a7faa4"
    $a3="7d12dddeaff695c2c74dc78043a7faa4"
    $a4="99a00bbcee1c23f9893ac5e313158030"
    $a5="99a00bbcee1c23f9893ac5e313158030"
    $a6="8f62e69c0919247c923b60a23c0e46b4"
    $a7="8f62e69c0919247c923b60a23c0e46b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}