rule nthash_hashed_default_creds_olitec
{
    meta:
        id = "6nJFG70gpXRIn0BODo2AkJ"
        fingerprint = "fa5b0b9232fa1be72ab1e9160d0bff531911d893fd3baf3abec99a97f4733f84"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for olitec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95c145f1150cc8683f3b736a5a62b4f2"
    $a1="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1)
}