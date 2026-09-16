rule nthash_hashed_default_creds_pikatel
{
    meta:
        id = "4m3niETS8rHeE8ayHPIiEZ"
        fingerprint = "86b57f5f2643197c654e172294413e2e0853d51c0f7de25d0f6668f846e1614c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pikatel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="302dfc8f4046ce06677a6e248dc56a79"
    $a1="302dfc8f4046ce06677a6e248dc56a79"
condition:
    ($a0 and $a1)
}