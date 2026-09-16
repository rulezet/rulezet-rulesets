rule md5_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe01ce2a7fbac8fafaed7c982a04e229"
    $a1="fe01ce2a7fbac8fafaed7c982a04e229"
    $a2="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a3="0d7cc6fdf3d432b7f0855713c50a1dbe"
    $a4="a33df7161cb7977492b0f07abb665627"
    $a5="a33df7161cb7977492b0f07abb665627"
    $a6="0baea2f0ae20150db78f58cddac442a9"
    $a7="0baea2f0ae20150db78f58cddac442a9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}