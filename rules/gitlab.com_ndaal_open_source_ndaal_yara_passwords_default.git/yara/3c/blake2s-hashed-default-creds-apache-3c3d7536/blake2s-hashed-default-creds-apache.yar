rule blake2s_hashed_default_creds_apache
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apache."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3316201dbb4e7f02221ac4d3a884b1807e10ef8c799f21f6db4e46fc8ad668f9"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a7="caeb6513252c04f10b19e00da9f5942a05f888c15793bfe513194f3ec22f034b"
    $a8="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a9="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a10="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a11="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a12="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a13="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a14="5211573598417a43a6cc4faffbe9eecc5e1588a7a26b7068cc6a3bed4d2f1647"
    $a15="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a16="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a17="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a18="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a19="b247485de967c91c22381477ffd22f6d6a47d17840838f9bc82d59ce194ee86b"
    $a20="6842e2f9d41bd74a4bca6730a202f3720a636871346da27a9d66a67f0b2c21d6"
    $a21="27f8b4c1066188eb30730d02a4f8107738f6a25b43ea0b1e973f0cd5820c7bf5"
    $a22="884b1ebe0f69d6c8963abec594114c57dcb5eef5570cbce561fe52131d82e7aa"
    $a23="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}