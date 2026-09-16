rule sha224_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="3d7ea88d6c869df3c7326230d4a3bbe76993f67ebade69e0e46b2bbb"
    $a3="6614945760a6568582ca94104cf566dd4931a41ac1546ea73acbd9dc"
    $a4="2c0e54538d2582098103c41da137dce369f51b8690cd1b8bcf3e0228"
    $a5="17d3983e8297628a6400a5e441b65c22372de7535f468ba18e889df2"
    $a6="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a7="974d62c38ad1996671df727d71e53f442fdba9f21bc35d4ff8eb5348"
    $a8="e2b1240397465c81daa159424a02be50867e0ba28da9a8748da91c89"
    $a9="4653c13e58206009fd28db9b079ee85d7b6238b422cd48c891bcb7bf"
    $a10="9ab8ba636aa941f12a5a2cead78f1464faad9d25237ca6ba3cb6674a"
    $a11="4a21a97d5cb6a370f3dc60470c542cef6ea268cc1df14a1b4e9f76d0"
    $a12="f459bcf13fc1869d739145c2cbe37d9ec0905f7310c1986f96718ace"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="d44d697d0b8ad27b1d3b323b1b438db88058ec1f0f21cef6a6629875"
    $a15="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a16="38ef1fe54a7fb1d97912261fad5be7d9ebb1d65da721c1ce3674eb5f"
    $a17="365e8da0aeb4aae7d3e9ab76558f6a7263c2f8eabbf79dc787a30210"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}