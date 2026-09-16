rule sha384_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a1="6e802f47b8d123f24b93f8d5cfcc091b76ae2c87411a75e6be23a2394f06944658bb9b300086ecdeb63d34db974846ce"
    $a2="4bd8d4ae7789627ae3cee9192ea7e13b26db483040f47d1c8fe094d66cb09b6807fe72cc700507afaea10f5fcd60ffdb"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="f87c1ebc04f901041f18dfb7d24bebc6d45e1cbbb2d9f005605e47afbc6d5d56356e3ee5f7762c5373219eb2ffd6554f"
    $a7="e576cef8e16baa7563bcc99495e677faff3ce7afe1104066285cb16331e90f5ab0df126cb04d4b262f8df1ffd8af63d8"
    $a8="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a10="3a43c3f59b84800d446186b88398a350fbfb2b46ed1ffeaf0f4285e15d708406bc2a710f29edb0a60918a68b47089da3"
    $a11="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a12="2340e5007830436d3e20f2b682ce17a72e6a4fa429e1c7004bd9ae9ebea5c43cf9ebd01f10397b6baebdd8b3410ae926"
    $a13="4b616013976cdc35c752303ac396019ea3e5b50a3c3cf8ead6efdff067e0c4f19fcec3fb37ed5298a51d644c968feac2"
    $a14="ad2649a34d1b07919a1c5886c89aa74809274c3c54cc44b0a18cdbf433e04172f953bd243da3bb6965681404f40b59b5"
    $a15="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a16="3e333bdcd4a8e043ca4d1266960829915639577294c9cec1743e0430234a8a779516642c12dc94adc4051e5f594dac6a"
    $a17="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}