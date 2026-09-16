rule nthash_hashed_default_creds_lg
{
    meta:
        id = "7XXQxl3HqMVVetMIQWbNVH"
        fingerprint = "db8835a7cca3d225c0c6ddb15882261d5e98b1cf3976a22bf02aa23e14ed4139"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lg."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c130686c5e7390f6dfb455744d6ca639"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="e5aa7d03e51d42108fb2a3af92619503"
    $a5="28c048b0a8abaac4447774ceb2aead22"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}