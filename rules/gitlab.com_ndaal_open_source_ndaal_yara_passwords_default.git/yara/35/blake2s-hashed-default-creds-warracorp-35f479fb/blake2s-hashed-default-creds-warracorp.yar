rule blake2s_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="208472508b6b56aad845ee6393d6afd784a3bef2951b1ed3406e810f36cf5e30"
    $a1="208472508b6b56aad845ee6393d6afd784a3bef2951b1ed3406e810f36cf5e30"
condition:
    ($a0 and $a1)
}