rule sha3_256_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f62fcd1a0266a63c61987cf35a4083aa9243a8d64c5772aa3caf0be1c61373b"
    $a1="3f62fcd1a0266a63c61987cf35a4083aa9243a8d64c5772aa3caf0be1c61373b"
condition:
    ($a0 and $a1)
}