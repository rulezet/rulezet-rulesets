rule blake2s_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a3="79e288aabff890a4eed9e879e9ceeca4dc704506bf7c17318defd9eaf98203bd"
    $a4="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a5="5b05808a9f43dc381814a59e5f9fe7d1ea654f0dd6ae73cebeb1bfab23b3fbaa"
    $a6="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a7="01aa412fae479c699ebd7dd2f4e9544dd444a089e053a54edbd21752b41762e3"
    $a8="8f0c8099d665b831109e78fc4a0364e34d2fe634eaa1e832b29c8af7c24af73a"
    $a9="8c0d7ae26386f2ac954ba3d826f9fbe7cba826c139c7cbb80f46be7fa694a03a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}