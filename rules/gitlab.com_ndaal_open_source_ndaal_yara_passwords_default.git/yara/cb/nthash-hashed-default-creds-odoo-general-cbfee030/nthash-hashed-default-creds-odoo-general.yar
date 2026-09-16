rule nthash_hashed_default_creds_odoo_general
{
    meta:
        id = "2f9etV3TQgQGwQuj3Xuotj"
        fingerprint = "27633319d08d4990ad7625620ac262d7a5849eac951f634683b93f070ae22480"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for odoo_general."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a3="527c9c819b286efb8ec4ebb5b5ae71cf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}