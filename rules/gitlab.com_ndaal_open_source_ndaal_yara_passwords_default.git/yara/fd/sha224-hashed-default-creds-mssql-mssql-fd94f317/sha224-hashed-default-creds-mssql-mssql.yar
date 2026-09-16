rule sha224_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b16fb3b924e301032472a00a31b2f40c96b19018bac9dc2713a870e8"
    $a1="ccc90fb04d0614ccb20bb44d30bee7f985bea6dafd22e2c8d81cb170"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a4="c9a2f5d2d923b4ce105ee3e1943ff5bff91ecd4c15960054752eb2f0"
    $a5="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a6="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a7="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a8="f63497db4871ace8b860d9ca4757a4a77a2494727b1fdb583dd54d51"
    $a9="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}