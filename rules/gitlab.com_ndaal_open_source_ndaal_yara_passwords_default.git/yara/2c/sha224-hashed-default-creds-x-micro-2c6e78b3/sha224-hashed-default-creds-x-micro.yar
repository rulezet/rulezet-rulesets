rule sha224_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
    $a1="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
    $a2="996ea0b1e9dc5363b84dc255d3d5bcfebf6f77beb1279c28bf953179"
    $a3="996ea0b1e9dc5363b84dc255d3d5bcfebf6f77beb1279c28bf953179"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}