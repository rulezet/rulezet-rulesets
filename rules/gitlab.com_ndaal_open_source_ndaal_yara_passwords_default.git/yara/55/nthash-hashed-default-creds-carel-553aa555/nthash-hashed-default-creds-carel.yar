rule nthash_hashed_default_creds_carel
{
    meta:
        id = "1ndgzxkqW1AcPKGagqD5Nu"
        fingerprint = "27d4e82052d8d4e44a85027c819cdfd58b6c26cc8a58fc2203b25dc2eb951459"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e222d2accc784a8a5b785ca939977238"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="bd62a39f78f9d8e5e7f18c45c08ef9b2"
    $a3="e1652f41fb194c8d4ec0cbe4a29d5aba"
    $a4="82211d6de11c4edb25c036c1f969cfe1"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
    $a6="cd6696218888fc07ff3bdfd044045b06"
    $a7="13c2c51c12aeee72a9f4bbf7354e094b"
    $a8="4366e392dbf0dd27fe6bd977792990af"
    $a9="209c6174da490caeb422f3fa5a7ae634"
    $a10="209c6174da490caeb422f3fa5a7ae634"
    $a11="209c6174da490caeb422f3fa5a7ae634"
    $a12="1dd14c820bcd1de7fbf36f2f8bae21b7"
    $a13="fb499578a8a2f14b7801868946ff2d12"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}