rule nthash_hashed_default_creds_symbol
{
    meta:
        id = "2fgJ3q9dVUOXY1RkwJ2aPU"
        fingerprint = "95c4f93777f1829a04ad021dc07519ea9da84ee56efa95662096f6537d8667bd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f78acdd0f6704711686ebcb6b062377"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="d2865109a99be943d8d8c5b73f25e789"
    $a3="d2865109a99be943d8d8c5b73f25e789"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}