rule nthash_hashed_default_creds_fortinet_web
{
    meta:
        id = "4LZSNanH2qDpaiBXQ7LiUs"
        fingerprint = "79b5aa7dd254fbf97fde166d0a0a401e0ea5b5d18528801172c5c0a301551520"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="08ff1d28010223d4f4482ffff047a40c"
    $a2="2244b09a26704ed42606717050eded5f"
    $a3="08ff1d28010223d4f4482ffff047a40c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}