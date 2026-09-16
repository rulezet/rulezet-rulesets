rule sha3_224_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50f790af2acff4bf64b7358d7d178cad3808f2d84414bb9bbdcfe79e"
    $a1="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a2="cf97cd55d38df3f5b2f18cf06ca8dcbebae08282c64c58088f80a591"
    $a3="015992deb8b7e19faa1bac5a81ef83e4a2d9684aee956eae318281be"
    $a4="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a5="459dd589b578ec3cdf231f0b6213f1c048e6a3ddd0c1c0ce63ca1478"
    $a6="da894a523ecfa6f6b52a8e9d8872608174d2be3952fc6bd76184db72"
    $a7="3c77a35671072d55f6995bac6450ea2ad943503143087eabcbc106b5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}