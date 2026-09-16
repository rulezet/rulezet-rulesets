rule nthash_hashed_default_creds_ez_systems
{
    meta:
        id = "1xEek9Ml3TR2LPdNCntTbW"
        fingerprint = "51e973a85810472fd2bf12e6bc051d8844cec6b6583d5f789f112f114d6dabc1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ez_systems."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3051f4f8e09cd9dd01b5e38d0d106ff8"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}