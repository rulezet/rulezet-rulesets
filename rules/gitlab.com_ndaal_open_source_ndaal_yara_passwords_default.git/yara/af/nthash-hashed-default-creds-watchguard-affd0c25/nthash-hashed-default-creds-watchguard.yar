rule nthash_hashed_default_creds_watchguard
{
    meta:
        id = "ewVNBbWGmhjQoPI9U44t"
        fingerprint = "e7056796170d07e6f846296af51c1c13add0188631a85d4b988053f5ba1ffdaa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36aa83bdcab3c9fdaf321ca42a31c3fc"
    $a1="57d583aa46d571502aad4bb7aea09c70"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="628427e87df42adc7e75d2dd5c14b170"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="dddbcb37e837fea2d4c321ca8105ec48"
    $a7="e3d83ea8259bb43662acccaf9c4352d1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}