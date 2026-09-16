rule blake2b_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="5d37c38d3a94242aa79b946556981480323fd757dbb086703d845e60e10078ba1ae3fc43bda86fa90c25aa416c9fb61eb1c5e01581a6fd7fcdbd02d8abfe9aa5"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="5d37c38d3a94242aa79b946556981480323fd757dbb086703d845e60e10078ba1ae3fc43bda86fa90c25aa416c9fb61eb1c5e01581a6fd7fcdbd02d8abfe9aa5"
    $a5="71746a5fb22fd342acf186d243652375a1d127d637e54150a6ca5798a2d5c6b1abd24f21e7e261e4e97b999fc52e72c8fd23e5afc95fc74121bc48d2742145ba"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}