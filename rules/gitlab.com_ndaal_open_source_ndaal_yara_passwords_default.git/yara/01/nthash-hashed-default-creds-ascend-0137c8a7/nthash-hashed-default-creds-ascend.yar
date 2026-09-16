rule nthash_hashed_default_creds_ascend
{
    meta:
        id = "5ub1b5opMGLKmW8JXMBkYA"
        fingerprint = "d9e0e2da5712c872e606b45e58b41647c16d78178428f98e04edc245c43816f8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c99036dd323323e9662f1cf97c217aa4"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="3212c03db38b7fb4ba4f1838b9b84e3c"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="0c4d36957773a3d3fc4dc1c692615ba5"
    $a5="dddbcb37e837fea2d4c321ca8105ec48"
    $a6="494062405d6c6ce94794d2431bb29c21"
    $a7="628427e87df42adc7e75d2dd5c14b170"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}