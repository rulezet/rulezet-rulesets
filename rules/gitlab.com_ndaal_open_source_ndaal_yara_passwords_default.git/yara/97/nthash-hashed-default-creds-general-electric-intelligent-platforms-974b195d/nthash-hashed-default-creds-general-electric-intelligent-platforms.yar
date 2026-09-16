rule nthash_hashed_default_creds_general_electric_intelligent_platforms
{
    meta:
        id = "SxXslaikqIjJYF0oZomiC"
        fingerprint = "2ce6dd16e60be54864fc47319078142e4e6ac135f054387dda9606b998df873a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_intelligent_platforms."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f441f41aa59214cccc3d4ba5ed1550cc"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="f441f41aa59214cccc3d4ba5ed1550cc"
    $a3="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}