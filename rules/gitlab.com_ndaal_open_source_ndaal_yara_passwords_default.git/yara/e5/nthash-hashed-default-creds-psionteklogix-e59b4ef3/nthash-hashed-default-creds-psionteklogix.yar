rule nthash_hashed_default_creds_psionteklogix
{
    meta:
        id = "5EfCHquAR3nXIb6uhIcCgV"
        fingerprint = "e7f06ec4f92b012129f58a6e8685c1b3b3305d0a9f8cb6ed93e39995db846b13"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psionteklogix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="6ed11202d209f9d4bea955a3615225fc"
    $a3="1e1dd34b128de1968a44212e05d9e942"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}