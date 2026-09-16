rule sha224_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d4fc2c43e8b403dd8b25f24b8dd85351fde69aa9f75efd1bc2bb3f47"
    $a1="d4fc2c43e8b403dd8b25f24b8dd85351fde69aa9f75efd1bc2bb3f47"
condition:
    ($a0 and $a1)
}