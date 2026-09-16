rule blake2s_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="13e7518f1bd3ca9fe63138b9b8dd5a42d0254f772abc22cd0cebae0670cd7528"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="ab4d1214cf24bfc4a4e4d2dd8b7f73ad8ba236fd3686130ffd23db17020ac7a9"
    $a3="f98599d8d902756dd66aaa949cb254986f7f361a1574e21ad5534fa19b18e455"
    $a4="36a8b72e8bc83524f1be81e514a709566fa2c7c11c86739937a38a977ce6ccf3"
    $a5="cd08df4577ca595cc717711c5ca24b6808ce578f8be67c75f0a13c8fe8523e18"
    $a6="e8af4daaa2fe1a5ddfd91792a2275a4dc692cc0db6244c9db2050ca17d4350b8"
    $a7="8795e415ea47e3387cf49a3a45de28958220085abcd097c980521d1b7599e6ac"
    $a8="4c7d8db1c3f3fcd06f80159186f42455496cfc4a9335429199ff41a0902d5e24"
    $a9="f901bf102a696e8e217c3d7c3ff8943208fa34cedba1edb459d56000bc67083f"
    $a10="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
    $a11="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
    $a12="82df5d0f14d06c6397cfbe0a928db4611f2837ca96ac0d60838d4b16d0d35dc8"
    $a13="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}