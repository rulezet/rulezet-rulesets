rule sha256_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7fe9dcbcafa8559ea3617a3a21af7b8aa06c2badf7322c67c5ee6b6f880cdb1"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="7b41e0b9e9f04ffc1d8fbc03525fdacdebf7140ccd2e99a3684265ff7523a618"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="d6cbfe3e2b49ab03980c1d095e95a916e41b152ddbabbd0dbe3bba37a63ce878"
    $a9="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a10="a8d304e8471af555b0079bacfb70810e4783b5454a6f836ba3c2f23452f3308f"
    $a11="862f957bff971a511b2a804c86639d819d6c5a78cc82800440a14316ce692fd0"
    $a12="04e43902471c9ab7935a25360a0c2dc5915d0bcb601f5bcaf1a9fcc97f3bacbc"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="7ea9dc2a17d2b8888d6989855d3d13a391ef17cef3551f67dd01724189064d50"
    $a15="e41a2b6503b00fb488a6cc399cb6815efc768916b9acf7819a2375cc56540a50"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}