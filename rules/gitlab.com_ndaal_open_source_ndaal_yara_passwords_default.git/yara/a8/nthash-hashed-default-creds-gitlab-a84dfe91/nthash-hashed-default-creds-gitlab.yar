rule nthash_hashed_default_creds_gitlab
{
    meta:
        id = "3t2rs6VNwys5DgEnOCyV7L"
        fingerprint = "e110876d94f4c6c4718b4cdcae82de2d9b1841eff3ebeb6392366ab3b630b680"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a98836559a04d1369a22055c3b889485"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a98836559a04d1369a22055c3b889485"
    $a3="43a220431a6d2839cbb2eb21c95a0239"
    $a4="a98836559a04d1369a22055c3b889485"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}