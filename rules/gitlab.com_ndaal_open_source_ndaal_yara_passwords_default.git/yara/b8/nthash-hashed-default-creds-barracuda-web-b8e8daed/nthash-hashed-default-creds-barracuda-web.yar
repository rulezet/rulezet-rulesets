rule nthash_hashed_default_creds_barracuda_web
{
    meta:
        id = "6jkU7B49yaf7FHdwOBDzyt"
        fingerprint = "d3705bcb662ec435b5c8d40151c23db37c53170c71a6efece0455a2c3ed0a0ec"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="f3dbea151f35ebf619550a6c4a03541a"
    $a3="f3dbea151f35ebf619550a6c4a03541a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}