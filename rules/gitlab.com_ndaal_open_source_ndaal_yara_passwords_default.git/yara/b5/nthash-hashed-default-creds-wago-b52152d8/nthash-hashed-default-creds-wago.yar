rule nthash_hashed_default_creds_wago
{
    meta:
        id = "3bv9ZjFFlLWlLjWma1ndZm"
        fingerprint = "16bb4e62e627c9429f4d79daa1afa06d3e7e0d11616a8845763a7db0d1cedea0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb2b560db95a7f6b1d76eeeb71a65161"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="57d583aa46d571502aad4bb7aea09c70"
    $a3="57d583aa46d571502aad4bb7aea09c70"
    $a4="823893adfad2cda6e1a414f3ebdf58f7"
    $a5="823893adfad2cda6e1a414f3ebdf58f7"
    $a6="4056da565eff865c23687b2d1cef8242"
    $a7="57d583aa46d571502aad4bb7aea09c70"
    $a8="d1554d6a00b55d64a531e3d2c2b3b026"
    $a9="478ef2a76e95338d441f681e20c2077e"
    $a10="fb2b560db95a7f6b1d76eeeb71a65161"
    $a11="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}