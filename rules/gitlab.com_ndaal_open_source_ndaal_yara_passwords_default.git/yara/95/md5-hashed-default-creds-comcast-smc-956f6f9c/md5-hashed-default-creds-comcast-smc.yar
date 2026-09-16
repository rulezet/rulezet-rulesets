rule md5_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="667f90b9ddee2049cd27685ebf10db90"
    $a1="257c2d1a0423a6a7c108632a8f963932"
    $a2="947f01331ab0db1b086a4fc91e7bda93"
    $a3="257c2d1a0423a6a7c108632a8f963932"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}