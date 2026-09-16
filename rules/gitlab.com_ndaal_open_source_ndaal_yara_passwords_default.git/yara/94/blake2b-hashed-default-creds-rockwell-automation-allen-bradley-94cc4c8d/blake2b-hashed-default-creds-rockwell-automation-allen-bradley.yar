rule blake2b_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="cc85e4608cc830bb25b6ef9d83cc7ba88bffa4218e344ba1d2e450a6ac2feba0a58727c67fd6c397549d0b6075592c6c2bdbc668a51a49cdd8aad758df53c66a"
    $a5="02dff1d4a359ef1a1b72f27938f55fc3f5c4ae5448e695955cf41d37bd3cbba8a85b84ba31eef2d84438ffe7e2285659abd9d098075ad6e71b8978213fae31db"
    $a6="cc85e4608cc830bb25b6ef9d83cc7ba88bffa4218e344ba1d2e450a6ac2feba0a58727c67fd6c397549d0b6075592c6c2bdbc668a51a49cdd8aad758df53c66a"
    $a7="9ee8242fdce3b8c0f2c4ce8a37a1e38b25e2218344496f4cbe3ad00ff419e37a13f098e189ef518a879dbdcbb0dab05a02463a6cc71e66e0cad684fe299001cd"
    $a8="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a9="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a10="9c2adba6cebddd0b577f169c051d027c8fe90d047bbd622fe6911d9620cd132aa6f223e025c73eab3e4ea0a60e83941a390b377b99b6d62d490320f6d1243d2e"
    $a11="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a12="07dd6553d8fe8ae0fa0dfccb05adad8fd136e9b77d26d5c9eef3a48842039ab53a09db8b956c16f3b53af529dc0a5c79ecd9a3cf00fcbb0b6e332c2b287c1a01"
    $a13="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}