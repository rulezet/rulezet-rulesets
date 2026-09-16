rule nthash_hashed_default_creds_asus
{
    meta:
        id = "6CF5oIjEjjIubgKu5vPo2P"
        fingerprint = "2cdfd6733920ffde5538d1dab9c764880b08c73ee0ead0e9e91b7f30c2aa54d9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asus."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="c37fbc56ce8d06beb4bc74288b191716"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="29eb4dfd242edee56514fe7ad5f165ef"
    $a9="2270d2eb171b38e659872814e1e9995b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}