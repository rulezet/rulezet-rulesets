rule sha224_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0b9a18fade599c043105a30e2fed85636f4e774eb6b5be4cdd6ead7f"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="f8af17f5aee0f7da705e922237e1e695bf74b087e189e9cf26d212e9"
    $a3="c417c5952fa1d63472b612f11e45809ea820ab918be37121fc257e6c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}