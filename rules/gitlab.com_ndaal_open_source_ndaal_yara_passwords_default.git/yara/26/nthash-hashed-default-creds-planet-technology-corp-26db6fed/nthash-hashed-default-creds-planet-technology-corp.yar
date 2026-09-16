rule nthash_hashed_default_creds_planet_technology_corp
{
    meta:
        id = "6F8Gx17kHs4CKDLXDQ4x6R"
        fingerprint = "efbe96467f010ace808bea4de5a319015ffd4bca5abb6ef61a84bfc797b0e50b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for planet_technology_corp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fba03a1b8646d8523fc4bb18c2180121"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="20cb42fa85bc81dcccb3ed161c6af54a"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}