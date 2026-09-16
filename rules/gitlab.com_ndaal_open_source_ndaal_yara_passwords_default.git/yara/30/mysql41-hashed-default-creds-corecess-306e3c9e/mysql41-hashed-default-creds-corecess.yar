rule mysql41_hashed_default_creds_corecess
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for corecess."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F416D521251B971077FE16D4B6A3239DDB902677"
    $a1="*F416D521251B971077FE16D4B6A3239DDB902677"
    $a2="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a3="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}