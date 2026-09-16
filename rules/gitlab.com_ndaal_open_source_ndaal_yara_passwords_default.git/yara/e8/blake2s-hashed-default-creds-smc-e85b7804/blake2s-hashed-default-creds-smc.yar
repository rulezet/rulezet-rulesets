rule blake2s_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a1="551ef0607965136474e543d944d5392e1bf3ea65224f77f90f7e524b7b88be25"
    $a2="4ffc5bdfd33a24fbe95c11c318697b883b15c93ef72d06b45e2660d1d75179fc"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="a3866d06cdac0a0e9d7286439fa10193cc2f8a9991444dff01a5c1b8955ee428"
    $a7="44e183ea2dab65f1b56afd25a3e6912535db21bb81e2a218b960ed0efad41f18"
    $a8="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a10="7258990f2fb6aae9a466871e9b7c8bb9d50dfbb71b872d30738ba6522488fdac"
    $a11="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a12="231a00cd8d05fda295e915f2c45410d3b529a0dbed95bdb181a7f1dea5e68a93"
    $a13="0d0ab17836ecbf9bb500e19a403333b23639558fd32ed3d95d2f6b9b8a52259f"
    $a14="9b47cc1fbf17788ec8a5fdc86e2ee8d92068623df36eae7217468620a17f639c"
    $a15="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a16="40fde414b5d75d32c01f34d9f05bd86752a4c3ff4244ae1c4071856eed0b19ea"
    $a17="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}