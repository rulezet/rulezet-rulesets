rule nthash_hashed_default_creds_ricoh
{
    meta:
        id = "5Ju60xt4mi1ILYo1MzqySN"
        fingerprint = "45f6e2d5ca40112b14004b752ea05b57a588f1f84103d95236133ec59cf48bed"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="cc607a8ad1d888e0ffbbc71539e6d864"
    $a4="94aa68f72ab39cfec7ffcb58dca3358c"
    $a5="94aa68f72ab39cfec7ffcb58dca3358c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}