rule sha384_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2baf38c2fcd6f440d85113b07992ee5893b111edc22d9b56126b63dff52e64894b204dac23dd04ffe3e51a33806b9ba1"
    $a1="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a2="7beb54af175116e20844620a98eba91f839419efd2bfa8d2c5c885fd736b7081a0ec1ad249bf081365a71c32605c1a92"
    $a3="22bd82ebe292d19f24ff56b1055ce899a27cd563698c8c8c0cb51e7920965370a5d6204f021546d40359f815a808c010"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}