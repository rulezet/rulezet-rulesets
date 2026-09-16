rule blake2b_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="b921dfa5a1afec1d93d31cf1260791a573940f55f8bb1c7a103026e31c2e0f8b9b0bf390b0900d5acdbd8a9961e8ec20b44df746ad5c47396bbc42f1fd32d5ce"
    $a3="b921dfa5a1afec1d93d31cf1260791a573940f55f8bb1c7a103026e31c2e0f8b9b0bf390b0900d5acdbd8a9961e8ec20b44df746ad5c47396bbc42f1fd32d5ce"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="fe9681601c6f0b52c12b1678f492a4d3c6e9316cd83fc95a0d8410ef48c9b9c25fa4c920360831f3928339c49f4dbf911b8ca0d9f17ae6acb1760f0ef5cb86cd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}