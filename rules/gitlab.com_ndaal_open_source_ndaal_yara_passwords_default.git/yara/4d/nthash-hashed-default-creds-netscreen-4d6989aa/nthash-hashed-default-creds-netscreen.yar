rule nthash_hashed_default_creds_netscreen
{
    meta:
        id = "4VD4emxBhrhsuNMBLwh9Oe"
        fingerprint = "8b1150dab488545e4d4821797320359fe816002be397f23e6db5d0c3169c919c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netscreen."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e41364f3191d288dceef6373c3b40634"
    $a1="e41364f3191d288dceef6373c3b40634"
    $a2="e41364f3191d288dceef6373c3b40634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}