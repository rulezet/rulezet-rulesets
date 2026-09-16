rule nthash_hashed_default_creds_sun
{
    meta:
        id = "Ea2k2nmnV6K82cSBTPsIY"
        fingerprint = "e58956458fd5e80c99f31b3a45cc9824b43c76efdb45c5eafbb31b0ca7519f8f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sun."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="6597d9fe8469e21d840e2cbff8d43c8b"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="c91ad2f7a9888288c71b8dff713a3075"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="6c65c1d0126bc589c803ffaf07025c6a"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="b5e3b0e4b2e4416607e23164ac0bc2a2"
    $a9="b5e3b0e4b2e4416607e23164ac0bc2a2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}