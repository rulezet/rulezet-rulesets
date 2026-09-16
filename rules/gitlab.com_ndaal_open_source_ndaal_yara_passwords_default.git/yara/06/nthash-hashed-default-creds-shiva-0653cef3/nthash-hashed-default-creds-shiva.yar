rule nthash_hashed_default_creds_shiva
{
    meta:
        id = "1RwoTHgx5aSlRiPSaXZUDl"
        fingerprint = "0f78fceb7b9dd0ffbde8f356fcc915d67e6c4670cd0e8a002dc91f69a22acce6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for shiva."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="066ddfd4ef0e9cd7c256fe77191ef43c"
    $a1="066ddfd4ef0e9cd7c256fe77191ef43c"
    $a2="066ddfd4ef0e9cd7c256fe77191ef43c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}