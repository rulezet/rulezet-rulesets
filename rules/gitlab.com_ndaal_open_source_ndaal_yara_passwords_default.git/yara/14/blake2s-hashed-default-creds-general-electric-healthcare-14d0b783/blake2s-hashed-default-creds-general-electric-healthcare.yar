rule blake2s_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a2="69c0fc0894d97a0a109c1322cca94287457509a69294996cf15227cf8bc70f40"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="69c0fc0894d97a0a109c1322cca94287457509a69294996cf15227cf8bc70f40"
    $a5="69c0fc0894d97a0a109c1322cca94287457509a69294996cf15227cf8bc70f40"
    $a6="60cbf99cbc066d31fd8f00b2f7a3d62ffe1d94f8d70aac6931d13ff3f208df9c"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a8="fe2348b7887dcb9e65ec9c4200b8f4a8c42a38b43f107691330dde4666e4845b"
    $a9="4e99c76486b8036bc1ef39716afa217b3bd855b78960250619f83d8caf804e8c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}