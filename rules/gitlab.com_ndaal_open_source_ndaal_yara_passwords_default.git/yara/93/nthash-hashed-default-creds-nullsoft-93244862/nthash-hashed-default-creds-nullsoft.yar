rule nthash_hashed_default_creds_nullsoft
{
    meta:
        id = "62QP6HnjNQRDRypZhY5Qhk"
        fingerprint = "f61e55a686cc17813960f1806bca189795f219280d8f25b749a75552e99a16d5"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nullsoft."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6597d9fe8469e21d840e2cbff8d43c8b"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}