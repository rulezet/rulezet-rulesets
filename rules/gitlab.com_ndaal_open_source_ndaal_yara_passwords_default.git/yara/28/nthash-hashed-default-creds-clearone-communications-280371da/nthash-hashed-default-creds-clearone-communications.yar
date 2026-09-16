rule nthash_hashed_default_creds_clearone_communications
{
    meta:
        id = "4SNniUpm1y2k51jRlcxNIV"
        fingerprint = "054d4931a9c98e44fae0dddc6e34c903deac5cf3adb6743337e1a382ce7d7d5d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fed850acfbd29174add53ba4d4a75818"
    $a1="674ee821426649f2ea50db43b0ae27dd"
    $a2="b4288fb6c01cd4d3d406cc6106207989"
    $a3="7baf939dbe9f1e3adc9fe7ef06e965d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}