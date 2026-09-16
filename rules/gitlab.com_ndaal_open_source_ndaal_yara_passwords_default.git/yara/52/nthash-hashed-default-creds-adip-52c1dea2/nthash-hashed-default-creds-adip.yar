rule nthash_hashed_default_creds_adip
{
    meta:
        id = "7OXFlLXKW953QjN617PqYB"
        fingerprint = "1bbb1b6402684f49c3f61714c1508a2ae34c15f964057a4e1258c58410e250c4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="af9c60da7ee8f4f6e0457877c756aa8f"
    $a2="63ac5736f63ecda15ac673bbc2f92f6c"
    $a3="af9c60da7ee8f4f6e0457877c756aa8f"
    $a4="37e94e23b45e1c95e55fdf81311973c6"
    $a5="af9c60da7ee8f4f6e0457877c756aa8f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}