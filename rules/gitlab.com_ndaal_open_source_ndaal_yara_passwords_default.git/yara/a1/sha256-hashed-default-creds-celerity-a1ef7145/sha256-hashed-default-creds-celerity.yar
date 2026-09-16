rule sha256_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b8180e90c61e2ed545d4fa82ff943f9842a874fd6fc0c6a28fc7f505cfb18815"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="6594a8fc77a70d4a0e7111c66509c0541fe511fc0e401684fa166fe6a75b008a"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="213e88ec8794cce8b7803294ec0992ffacf88abef89f6aa4faaa3db80e792383"
    $a5="213e88ec8794cce8b7803294ec0992ffacf88abef89f6aa4faaa3db80e792383"
    $a6="a3c4ff03c78ff2ede7e8942527a9cb80e95956cbe0d92fe5772890fbc28d492b"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}