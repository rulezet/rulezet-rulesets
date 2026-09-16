rule nthash_hashed_default_creds_idirect
{
    meta:
        id = "FlnTmoGWA1jne6XglpaqP"
        fingerprint = "b731568d1f945fcc05633e99bbd5f493f0931f717d946cdcbed134f92b40252b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for idirect."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc23a1506bd3c8d3a533680c516bab27"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a073738d2727206ed27747d8dc4c4903"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}