rule md5_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73acff6caab1d3454f11b9d4c8acdc49"
    $a1="3465acd996cab3e6cf06371ef49b86a8"
    $a2="73acff6caab1d3454f11b9d4c8acdc49"
    $a3="d37324d140b3f4d6b240af36062f4d5c"
    $a4="73acff6caab1d3454f11b9d4c8acdc49"
    $a5="418560b5bad3529b8ba438d1b7fd8bdd"
    $a6="319f4d26e3c536b5dd871bb2c52e3178"
    $a7="3dd6b9265ff18f31dc30df59304b0ca7"
    $a8="c2ba7e785c49050f48da9aacc45c2b85"
    $a9="c2ba7e785c49050f48da9aacc45c2b85"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}