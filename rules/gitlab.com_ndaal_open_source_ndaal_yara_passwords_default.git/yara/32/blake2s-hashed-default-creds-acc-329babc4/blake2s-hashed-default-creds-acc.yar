rule blake2s_hashed_default_creds_acc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
    $a1="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
condition:
    ($a0 and $a1)
}