rule nthash_hashed_default_creds_rsa
{
    meta:
        id = "5ZFWuo8SfcCMjAxTN2wppk"
        fingerprint = "ba0a41bc8662c3bb62d044d7f975c78a8066ca85b3934c27e81a69641c9e8a7c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68bbbb18b3c27d941cb6224353be1d0a"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="33e081dd66b2635490eff5f43eb5ea05"
    $a3="a4141712f19e9dd5adf16919bb38a95c"
    $a4="3ede5e48b63167f908e5a55973953892"
    $a5="6d3986e540a63647454a50e26477ef94"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}