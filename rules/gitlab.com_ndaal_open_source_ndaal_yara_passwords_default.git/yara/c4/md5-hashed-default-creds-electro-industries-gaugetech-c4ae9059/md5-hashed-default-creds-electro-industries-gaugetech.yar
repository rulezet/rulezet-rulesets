rule md5_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="294de3557d9d00b3d2d8a1e6aab028cf"
    $a1="294de3557d9d00b3d2d8a1e6aab028cf"
    $a2="aafde1d9c8d533528e4821b681f80a19"
    $a3="3ba14bc6148a0f0a6fcbba157e578ac3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}