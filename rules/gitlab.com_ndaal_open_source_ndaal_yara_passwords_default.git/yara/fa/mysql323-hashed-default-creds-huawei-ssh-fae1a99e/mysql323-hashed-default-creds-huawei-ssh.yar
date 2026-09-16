rule mysql323_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="43e9a4ab75570f5b"
    $a3="4077eb0b03ddce3b"
    $a4="2ae5daa30ce0708c"
    $a5="2ae5daa30ce0708c"
    $a6="79c18c201c93957a"
    $a7="055f297c5a36d5df"
    $a8="607134f47c790258"
    $a9="1a486e7929011a28"
    $a10="1a486e7929011a28"
    $a11="1a486e7929011a28"
    $a12="37f608604fc1b61a"
    $a13="37f608604fc1b61a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}