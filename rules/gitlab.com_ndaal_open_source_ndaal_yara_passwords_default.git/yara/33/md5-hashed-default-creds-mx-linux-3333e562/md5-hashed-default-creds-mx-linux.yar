rule md5_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe01ce2a7fbac8fafaed7c982a04e229"
    $a1="fe01ce2a7fbac8fafaed7c982a04e229"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="8c51e80a21db87219dd28f4f8c6b633c"
    $a5="a31e7e9c38fad7b2d947ca335b232ced"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}