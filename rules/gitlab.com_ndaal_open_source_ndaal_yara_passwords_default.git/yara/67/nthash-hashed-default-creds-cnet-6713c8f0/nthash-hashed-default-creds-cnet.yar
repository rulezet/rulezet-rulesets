rule nthash_hashed_default_creds_cnet
{
    meta:
        id = "1ETR1TP5KZ9OD5m0o33uPX"
        fingerprint = "533a02fedea0abaf07b26588cc30519ffbaaa639d63f803b4bbb018f494a058a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cnet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c130686c5e7390f6dfb455744d6ca639"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="209c6174da490caeb422f3fa5a7ae634"
    $a5="a25b2710ba9de114396adc7dfb0a7235"
    $a6="c130686c5e7390f6dfb455744d6ca639"
    $a7="a25b2710ba9de114396adc7dfb0a7235"
    $a8="8846f7eaee8fb117ad06bdd830b7586c"
    $a9="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}