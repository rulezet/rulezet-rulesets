rule nthash_hashed_default_creds_brother_hl_series_printer
{
    meta:
        id = "769e14xnYw9OsDWPCpcofY"
        fingerprint = "af94fcaa8870fa70de38d7a5bd1b09b16cd37915fbcce50fba01c81d4d249855"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brother_hl_series_printer."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e6342ecc5ed563057800830d710dd61"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}