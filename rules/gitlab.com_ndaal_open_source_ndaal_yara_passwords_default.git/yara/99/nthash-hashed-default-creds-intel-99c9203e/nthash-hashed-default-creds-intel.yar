rule nthash_hashed_default_creds_intel
{
    meta:
        id = "5sX9EdEUKLCJDPlXuqBYCG"
        fingerprint = "7918f213ce23d7d10caf899cf472429a2d1205070ef83f5314227d7df4b3bc09"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6aebf95ee750d35a58d279ad1fbf32b"
    $a1="e6aebf95ee750d35a58d279ad1fbf32b"
    $a2="1ff6c0516b6474949b991080492769c9"
    $a3="1ff6c0516b6474949b991080492769c9"
    $a4="4a946b221b3685ed1b0047d379173cda"
    $a5="4a946b221b3685ed1b0047d379173cda"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="d334ac74f9e3de9750e64b6583af424d"
    $a9="c64157f52f567fe73b7f09a54d83e323"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}