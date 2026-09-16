rule sha3_224_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7df411cedc8e99ea114bbf471ed7a746c47ae08aff9559016b56dce"
    $a1="6919dc4d90fe8ff055711ab9bfbad469c87de5ad773a1cc717125107"
condition:
    ($a0 and $a1)
}