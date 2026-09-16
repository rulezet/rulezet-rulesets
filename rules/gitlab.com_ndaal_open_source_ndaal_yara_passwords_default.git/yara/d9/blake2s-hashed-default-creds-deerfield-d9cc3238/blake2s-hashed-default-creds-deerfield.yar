rule blake2s_hashed_default_creds_deerfield
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for deerfield."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0cc3a9f807ee07831eb33d0c2ecd69baa292360e1327f9b661e7749187b91738"
    $a1="15c1e0c8b23f515c776ad050607c905477016919d146eda236a0a965af9f3e09"
condition:
    ($a0 and $a1)
}