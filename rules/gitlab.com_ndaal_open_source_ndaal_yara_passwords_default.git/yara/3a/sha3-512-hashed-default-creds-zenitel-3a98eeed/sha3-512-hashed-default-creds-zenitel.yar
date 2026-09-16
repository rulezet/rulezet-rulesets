rule sha3_512_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f499790d738f251e00b6d0070a6b80628f914b0982134117945472413ceebaa569b273bae2e483d623a977ae454503e537886853993d41b8b3eac11ca5bd59a"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d88d5a0fe93ec16e99f580d2ecab5f0583535497ab7f6e8b5ae021bb06e29201ec666f80b3c7082868c1e1cf7e8d938cc65a0c1eb661355d93e59bf625cc3807"
    $a3="b12c327f742aac769cc3a8ebcb2dff2cb6bbf4ef7f8edd42ab65dbebb1cff8e72da7eef015355396474167708e54248fc8989a86b2da61c84f8fc5d500d2bd11"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}