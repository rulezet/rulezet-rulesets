rule md5_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa1d78f3088c0dbba0f00edae73c01fb"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="0352a4836f051450594c4d68277a3529"
    $a3="0dd439cf8f77110908a897d1aadfcd86"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}