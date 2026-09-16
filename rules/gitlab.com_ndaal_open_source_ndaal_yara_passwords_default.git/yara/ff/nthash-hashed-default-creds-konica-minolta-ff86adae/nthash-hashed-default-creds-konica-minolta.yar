rule nthash_hashed_default_creds_konica_minolta
{
    meta:
        id = "7fgEnzUdn3ckXGC7IVyuEx"
        fingerprint = "83d85ca0e7729d9156e67084e5e8a892a89ff87515d7f408cf6ee74825757a7a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for konica_minolta."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4141712f19e9dd5adf16919bb38a95c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}