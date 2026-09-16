rule nthash_hashed_default_creds_bintec_elmeg
{
    meta:
        id = "1WOgvQVycr0fHri8Q6t76h"
        fingerprint = "4033a29cb23c1d65c058b34b0af468ca0202f52a42296263130741f5b86ed7b2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec_elmeg."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e48bcc94ef0e09f090779ff0d78acd0"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="f1e08e22f365da1556331f62fc370997"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}