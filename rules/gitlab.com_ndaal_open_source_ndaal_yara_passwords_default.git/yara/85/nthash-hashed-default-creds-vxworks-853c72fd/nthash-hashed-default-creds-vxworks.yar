rule nthash_hashed_default_creds_vxworks
{
    meta:
        id = "42o0OgsIgpR1ixVjkxdQYl"
        fingerprint = "bae1c447605a6e81570a08095dfafe910c0b69be00d69d945b545c5aba4c63e8"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for vxworks."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="823893adfad2cda6e1a414f3ebdf58f7"
    $a3="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}