rule blake2s_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47f17c90713a26870661f3a7db598dd6ed834bad229a5d77c2d337ce2c41d2c9"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a2="b4555021bf8e26dbe3a2c2dacdd0d4295e3f765a577cd17e7f6d146587d4ed5c"
    $a3="7062dbecf4252422905bbd339a24447612d9f5b7d9aa7338f30511eb943cdd4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}