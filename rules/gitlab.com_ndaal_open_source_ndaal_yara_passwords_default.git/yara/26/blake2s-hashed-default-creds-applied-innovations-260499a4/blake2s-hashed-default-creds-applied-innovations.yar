rule blake2s_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc02ef56193d205e8bd829b602cebedaea4d83c55cdd3918c96f1dd16c5c1ac4"
    $a1="dc02ef56193d205e8bd829b602cebedaea4d83c55cdd3918c96f1dd16c5c1ac4"
condition:
    ($a0 and $a1)
}