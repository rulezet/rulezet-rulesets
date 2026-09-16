rule blake2b_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d04114cf2db95aeea46ba3cc57cb1e0494f78355cf28b92ec02b1bb68cbcad8b7ca3640827f207754488ebcff8a63a9ffeabc22e2c61ce060b7e6538bf166a76"
    $a1="d04114cf2db95aeea46ba3cc57cb1e0494f78355cf28b92ec02b1bb68cbcad8b7ca3640827f207754488ebcff8a63a9ffeabc22e2c61ce060b7e6538bf166a76"
condition:
    ($a0 and $a1)
}