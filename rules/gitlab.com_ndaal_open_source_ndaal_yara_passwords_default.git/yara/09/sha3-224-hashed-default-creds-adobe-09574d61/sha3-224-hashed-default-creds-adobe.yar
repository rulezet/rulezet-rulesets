rule sha3_224_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="048650084a17424689f234c16e30bc710f40de388536e24283c86dd2"
    $a3="048650084a17424689f234c16e30bc710f40de388536e24283c86dd2"
    $a4="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a5="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a6="ae9f7a6af2b4e503b5f6f1aa848e85c59383373817ba24ea9cf87a66"
    $a7="5acff48817eb3b6d1fdac91d6d5b7aa8b41aeb9578315bc18f03148e"
    $a8="66fef3e134760b5566d20969354052c4b085733678c2a49513ca96d1"
    $a9="9ff6781bd68aab282a8cd5e204d786ac4015ead2d01d94617a966304"
    $a10="b33536a4cf58ca8f8033bba1389bdba58c9a76aabee492dfd7411e1f"
    $a11="b33536a4cf58ca8f8033bba1389bdba58c9a76aabee492dfd7411e1f"
    $a12="44b088f65bb1d675c5de5989d1dd7ddd854a54b85309cb68317beb62"
    $a13="44b088f65bb1d675c5de5989d1dd7ddd854a54b85309cb68317beb62"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}