rule nthash_hashed_default_creds_draytek
{
    meta:
        id = "4AufezNmGwEuiTrO6RDdjH"
        fingerprint = "a43347d71e75761ee34e36527ee969f5a9ad0c2dfbf5dfa0c42cbaa01ec30fa2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for draytek."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="b681bdfdc25f3b77c845afa7738ebe78"
    $a4="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a5="85f145d85323de118f7d7706a0aaa0a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}