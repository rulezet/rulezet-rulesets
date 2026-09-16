rule blake2s_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="ea7a4d7608d54874a6e5188e1879d37bf168713dab66cc635c69272c2d5dcd85"
    $a3="ea7a4d7608d54874a6e5188e1879d37bf168713dab66cc635c69272c2d5dcd85"
    $a4="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a5="799fa5e1df7938d3dca0080ec72e76c9dbfd19a975bab404cd6c4d54338db190"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}