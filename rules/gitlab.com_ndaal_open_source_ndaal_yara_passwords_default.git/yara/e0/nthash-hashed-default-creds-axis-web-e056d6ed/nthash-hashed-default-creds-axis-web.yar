rule nthash_hashed_default_creds_axis_web
{
    meta:
        id = "6slKsGU5uhO7n0K1z6qzy6"
        fingerprint = "f4ba2dcf95c511341c44587c5ff045f47313311283f710bb4c27eaf6fb3d3efa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for axis_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="36aa83bdcab3c9fdaf321ca42a31c3fc"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}