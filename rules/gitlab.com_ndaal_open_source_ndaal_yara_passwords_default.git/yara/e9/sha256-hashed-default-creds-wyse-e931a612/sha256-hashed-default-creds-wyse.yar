rule sha256_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04e43902471c9ab7935a25360a0c2dc5915d0bcb601f5bcaf1a9fcc97f3bacbc"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="7ea9dc2a17d2b8888d6989855d3d13a391ef17cef3551f67dd01724189064d50"
    $a3="e41a2b6503b00fb488a6cc399cb6815efc768916b9acf7819a2375cc56540a50"
    $a4="a8d304e8471af555b0079bacfb70810e4783b5454a6f836ba3c2f23452f3308f"
    $a5="862f957bff971a511b2a804c86639d819d6c5a78cc82800440a14316ce692fd0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}