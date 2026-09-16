rule sha3_384_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a46f29a6cb8cf6ece21d71e1e888c4ced518c25efc0f262efd62ab248a4baf3139e7854082f9af0b5ebc1bb02a4e5457"
    $a1="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a2="64dfb65e747323846aae58781fd8db6f6b811bd99caf4c1dad293b101042f12336f3035d7cd44e333f308a35aa8c25cc"
    $a3="3efdf8d53a6e0b2833efe8caec234b3630ba633bf9288201f8a33b4fb0b47a253e0023deb921380ecfc1929fdf688816"
    $a4="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
    $a5="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
    $a6="de7dfcfc3ca6ee8d4f4944e89853e4f47d2325178761f052c482d9f31db0e1bb88837b0fc197a240283c7f89ec292370"
    $a7="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}