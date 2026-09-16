rule nthash_hashed_default_creds_triumph_adler
{
    meta:
        id = "7TVA3PxhbU5qsaWoi8e44T"
        fingerprint = "a58a009e7de0c10048f56b71c6cc1b6835c0c60e25bfc43ebfd6451e1bd63073"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for triumph_adler."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7bc26760a19fc23e0996daa99744ca80"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}