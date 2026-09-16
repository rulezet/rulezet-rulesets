rule nthash_hashed_default_creds_supercook
{
    meta:
        id = "VwagBPKZTW5ys0cFRtAwu"
        fingerprint = "ef939191d3c4bb966c1ce95c427b68aa8d9e78cdf6ea1f561e8a782080ae7cfd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for supercook."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f94830ceb1afe74f861fa9df6750f39"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="fad2607eda55ca3ecf8d89067ee91f84"
    $a3="fad2607eda55ca3ecf8d89067ee91f84"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}