rule nthash_hashed_default_creds_greatspeed
{
    meta:
        id = "ruxQsxZtkS5G7KLBxyUIH"
        fingerprint = "b714e795031907416f10b27fda18154ec72a1cdfb921fe26503714a92da77321"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for greatspeed."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a2426e6b817332e26bb52f8825880168"
    $a1="e2003ea1b0309acb195f977cd6b66135"
    $a2="0cbd63411fa71cfe2970265f9df7911f"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}