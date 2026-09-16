rule nthash_hashed_default_creds_ampjuke
{
    meta:
        id = "6Jp5iWje2N33mtfxwUVMM2"
        fingerprint = "2b869a0359631d942c854277f70e4f0aea02c2c2c57b8ba3293713cb87144e04"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ampjuke."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36aa83bdcab3c9fdaf321ca42a31c3fc"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}