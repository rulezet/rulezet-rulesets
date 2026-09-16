rule sha3_512_hashed_default_creds_vpasp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for vpasp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="02f68e108ae3bc05747275cd894878e2ecaa4fa3dd19dbe149f2853e7dbdc155e94957ed07548f52d047d412a53979a48c1f432c3c4c64ef04c6604752b80492"
    $a3="02f68e108ae3bc05747275cd894878e2ecaa4fa3dd19dbe149f2853e7dbdc155e94957ed07548f52d047d412a53979a48c1f432c3c4c64ef04c6604752b80492"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}