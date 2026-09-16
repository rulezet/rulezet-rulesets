rule blake2s_hashed_default_creds_apc_ups_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_ups_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
    $a1="84e7a52c2aeb742db764216915a08aa986408f5f85e3b26cc9a5b1ac9e9eb719"
condition:
    ($a0 and $a1)
}