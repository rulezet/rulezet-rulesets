rule nthash_hashed_default_creds_utstarcom
{
    meta:
        id = "6UdLxJ86OaeIvGiIqz0QMQ"
        fingerprint = "60a8f12b72185faae8f6086c0d15bbeb379f4f88be21780e30723349ec1d4c0f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1a69dc6ea5b3f1ced1d5c1fd2e9f786"
    $a1="f1a69dc6ea5b3f1ced1d5c1fd2e9f786"
    $a2="9026e5f70e9bafaeb0dbf7257872245a"
    $a3="0b3354bbd382542544610d7649446e4e"
    $a4="c3a23eb3f9e371403d51ab7a5810d2c1"
    $a5="c3a23eb3f9e371403d51ab7a5810d2c1"
    $a6="27db353b7291d17f3ebc1fdc672a4630"
    $a7="27db353b7291d17f3ebc1fdc672a4630"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}