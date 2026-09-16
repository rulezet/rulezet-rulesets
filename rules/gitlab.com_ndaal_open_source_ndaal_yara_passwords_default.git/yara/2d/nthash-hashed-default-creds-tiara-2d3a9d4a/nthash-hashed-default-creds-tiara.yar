rule nthash_hashed_default_creds_tiara
{
    meta:
        id = "7Ihc52iRQYTem8QOrLMCXc"
        fingerprint = "3758d6ffb449c72e3f82466523d5b819af1add4407d9f69e45fae40461b4297d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23626add1673bb15fe516d023829bc10"
    $a1="81e5e425b5cd4556e9df4926c46fb0d4"
condition:
    ($a0 and $a1)
}