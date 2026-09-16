rule md5_hashed_default_creds_beckhoff_automation_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beckhoff_automation_gmbh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4ca4238a0b923820dcc509a6f75849b"
    $a1="e53a12c1ab9c894d183ce0b575e4fef5"
    $a2="c4ca4238a0b923820dcc509a6f75849b"
    $a3="7b7bc2512ee1fedcd76bdc68926d4f7b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}