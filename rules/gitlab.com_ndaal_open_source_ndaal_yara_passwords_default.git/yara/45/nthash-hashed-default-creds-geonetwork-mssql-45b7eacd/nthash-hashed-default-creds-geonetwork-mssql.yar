rule nthash_hashed_default_creds_geonetwork_mssql
{
    meta:
        id = "ltYr4GqBRpq3P3XO6JFRY"
        fingerprint = "0ab43ec02a94d4479cc18cd9fd6cd43dbbbc1a86b4436d81d2e039841afd19f6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for geonetwork_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2f5da38bcde7f7ca971fdf03db0f2a85"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}