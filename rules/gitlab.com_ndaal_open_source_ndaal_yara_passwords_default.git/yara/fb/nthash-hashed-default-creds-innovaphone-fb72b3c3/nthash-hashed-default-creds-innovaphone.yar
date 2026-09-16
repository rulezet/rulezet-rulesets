rule nthash_hashed_default_creds_innovaphone
{
    meta:
        id = "1tXn6bRMyQCZuLRSFmqrCs"
        fingerprint = "a3682d942e5e8c871d24c9bd159b7f98ad8532b4875bd07b0399aa6989a9eea9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5713166c244e9b76453e33d7b0108a8"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="d253da24a4a08d782353b67fdf43b50a"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="5a2fd9f024799c287f6c1a7308a9b4a4"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="af7bb4de6e9865c99768742dbec245e0"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="baf7063de5f3a6fefa025ee13ef22f1c"
    $a9="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}