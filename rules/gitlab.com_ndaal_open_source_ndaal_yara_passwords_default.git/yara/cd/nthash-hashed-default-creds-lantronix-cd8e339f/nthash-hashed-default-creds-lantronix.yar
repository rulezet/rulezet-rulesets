rule nthash_hashed_default_creds_lantronix
{
    meta:
        id = "2zMwsZpAxVvbi2uJbuDrGV"
        fingerprint = "4f8943ce2541b95a579dd8049dcf190be3c00fd14ad6cf3aa0b0fa5fd31cbcbc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f441f41aa59214cccc3d4ba5ed1550cc"
    $a1="724279aa825e91ca54a5cc1db868bd4d"
    $a2="9000b201bdef274265885986a8cf50a0"
    $a3="cc607a8ad1d888e0ffbbc71539e6d864"
    $a4="4e6342ecc5ed563057800830d710dd61"
    $a5="e6bd4cdb1e447131b60418f31d0b81d6"
    $a6="9000b201bdef274265885986a8cf50a0"
    $a7="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}