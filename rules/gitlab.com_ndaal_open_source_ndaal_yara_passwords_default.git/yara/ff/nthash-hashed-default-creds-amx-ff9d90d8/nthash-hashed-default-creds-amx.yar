rule nthash_hashed_default_creds_amx
{
    meta:
        id = "4rJDUwYQup3uaKpOCw4iNV"
        fingerprint = "d6ed5677d7bbb98fa34768371c5434493e7aa9e20814e5fb498225bd6ee2fe9d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c811a1c05af7c5485a6a5eaad8f9e481"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="a4141712f19e9dd5adf16919bb38a95c"
    $a4="714f83f9c3ac423fcee1b8f980937a9b"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="8846f7eaee8fb117ad06bdd830b7586c"
    $a7="bd02c0eaff2a8b1d107b7d280c0899e3"
    $a8="c811a1c05af7c5485a6a5eaad8f9e481"
    $a9="a25b2710ba9de114396adc7dfb0a7235"
    $a10="823893adfad2cda6e1a414f3ebdf58f7"
    $a11="823893adfad2cda6e1a414f3ebdf58f7"
    $a12="209c6174da490caeb422f3fa5a7ae634"
    $a13="209c6174da490caeb422f3fa5a7ae634"
    $a14="8c5660f518240f264fc71803105b01e6"
    $a15="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}