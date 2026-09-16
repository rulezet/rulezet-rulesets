rule nthash_hashed_default_creds_conexant
{
    meta:
        id = "1jwXpds1ygVdkN5H6FSCLO"
        fingerprint = "e1914d52b3bdec7e45affe1486794111d71b7f24db0c6acdd42b1dc9e9cfb110"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conexant."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="bed89bee5026a8829e1303ecd956912b"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0e131d6b6eaa882f4147e9dfbc496170"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="c130686c5e7390f6dfb455744d6ca639"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="8846f7eaee8fb117ad06bdd830b7586c"
    $a9="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}