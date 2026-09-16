rule nthash_hashed_default_creds_broadlogic
{
    meta:
        id = "5UctL4Y3RwzoXzYntPPyIC"
        fingerprint = "eb22390a554a04d87d70a8dcca4d0561008b124c03905f8eceb25663f05f1f97"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3726db814d2c2a76946e80c5d006408e"
    $a1="3726db814d2c2a76946e80c5d006408e"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="a37c2cd2c0a5415745e9d1fe1a0d6367"
    $a5="a37c2cd2c0a5415745e9d1fe1a0d6367"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}