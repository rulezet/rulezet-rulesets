rule nthash_hashed_default_creds_jde
{
    meta:
        id = "1VOezClew7wOHiuaZn308T"
        fingerprint = "ff791ffbd708aaf77a210adac44e09923e2b437c8247044403c0bd76785d25fe"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="659dab44405f414f81d8491c09499b7a"
    $a1="659dab44405f414f81d8491c09499b7a"
condition:
    ($a0 and $a1)
}