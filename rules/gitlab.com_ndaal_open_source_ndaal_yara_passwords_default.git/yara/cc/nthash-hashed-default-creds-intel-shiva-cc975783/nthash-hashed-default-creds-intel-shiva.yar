rule nthash_hashed_default_creds_intel_shiva
{
    meta:
        id = "69Rjkpd2MaZmxUIe9ZZ88N"
        fingerprint = "9d05f7d87a568aabc1160d043d3b85612747a44f80f9ce216f488df0356aad95"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel_shiva."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="066ddfd4ef0e9cd7c256fe77191ef43c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}