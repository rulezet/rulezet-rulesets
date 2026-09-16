rule nthash_hashed_default_creds_pirelli
{
    meta:
        id = "5J9JLdYQBs3jOVH5VYHvFz"
        fingerprint = "950db735db21b69584a1ae023fbbd6460e5089ea323ce65f7ae1c62154c0829a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pirelli."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3792aa0b36818e759d9ef196b169ae2"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="57d583aa46d571502aad4bb7aea09c70"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="ff140a0b382fe05854fc4ee0eb58ed8d"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="326e3bccdeba3c765dd1589cd3168a33"
    $a9="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}