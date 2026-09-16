rule blake2s_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a1="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a2="af6a96f08629a1ce62a4f187a682f649068007fe3793e2ba057967f6ddb284f6"
    $a3="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a4="6d2dde5b9ba3dabce745ae144372bfb3c58d5fe900679fc9d19e30849fdeb83e"
    $a5="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a6="620937a23796d8dbe7c34a0db6b47ae6a3f43d9b323b3c9f8a1fd68d59929b39"
    $a7="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a8="af6a96f08629a1ce62a4f187a682f649068007fe3793e2ba057967f6ddb284f6"
    $a9="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a10="6d2dde5b9ba3dabce745ae144372bfb3c58d5fe900679fc9d19e30849fdeb83e"
    $a11="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}