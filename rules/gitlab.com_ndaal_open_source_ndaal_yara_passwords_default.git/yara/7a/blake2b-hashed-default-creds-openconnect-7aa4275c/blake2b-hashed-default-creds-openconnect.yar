rule blake2b_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a3="4c91adb357eb774fb98827c5194cfdc456fc42c7616e0a08c5b4e31d801dd3ca641db4165460fcac54c32831112a0fe601691bbc12212df90cde2be954c9c707"
    $a4="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a5="4b4efdf6002f8cf809bbc9452d8f0790262866164350ff0bf7bb57786c5378172fdf7d740554abc678998a82f45033c76d9eba7253106f9f527670854e6670ab"
    $a6="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a7="4a30f07d4ff6efdb38e93ae369bafd005d1dc745c72ca901d58bd6aba1487bba4264126cd52ddc50537403e562f5b82cc20d8793a93c0ef0976c2b7da07e3a12"
    $a8="46c1415ed84d84d02c5a07dd8c674a5ddbf258c3aa8705101f8225e74c605713cbe732c6614188b7e9eb581e740ed76cb47566a1c3628c1276b1e908f393268b"
    $a9="6f6426bae1da8bd45b1bca5a1feb777caa3fcbd1939774739a639b28f6a56dd649a908da4e60145cb00516c320448a9314f8b617cebc4cff1a4620751021edd5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}