rule blake2b_hashed_default_creds_warracorp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for warracorp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ee98fd2f70bf0e7502a2fe399557fe972b48ed8e217b4cc345ae12963fe5c62dea6fd72f8413d0d4a8b4ffaa998e343375e72aae4963232cdc6ef3d92ef2948"
    $a1="9ee98fd2f70bf0e7502a2fe399557fe972b48ed8e217b4cc345ae12963fe5c62dea6fd72f8413d0d4a8b4ffaa998e343375e72aae4963232cdc6ef3d92ef2948"
condition:
    ($a0 and $a1)
}