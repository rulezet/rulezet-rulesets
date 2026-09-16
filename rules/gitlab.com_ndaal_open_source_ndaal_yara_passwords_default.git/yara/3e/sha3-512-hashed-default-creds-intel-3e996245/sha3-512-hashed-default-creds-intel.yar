rule sha3_512_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a1="ae0380de40c9c59e8e0455a4272e9f74bad7dd08108e5fd44c09eaef705ef5b8ee2aba8152b186f067c2235a197f3c88af2010bba3a610ff60c7ac2f8c35b4b7"
    $a2="65582c103cfe2fa6e4e23596c7d51ed0da89c9b73252d895699ae657ed44852d1f28817bd30eb0702f3b7704be8e7516c850f1c33a16352cff75e492754f643f"
    $a3="65582c103cfe2fa6e4e23596c7d51ed0da89c9b73252d895699ae657ed44852d1f28817bd30eb0702f3b7704be8e7516c850f1c33a16352cff75e492754f643f"
    $a4="3d7f62b722396d23601c47721a8a83e88d733b4662bcb83da676be4604200c24fec1db69232bff6b861e65fc8ae736d38f7ee22127b574b4d5df330fd9a8d976"
    $a5="3d7f62b722396d23601c47721a8a83e88d733b4662bcb83da676be4604200c24fec1db69232bff6b861e65fc8ae736d38f7ee22127b574b4d5df330fd9a8d976"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="1c6daab50a77e6e9afd594657a053c60091f1560df238156a58444d71765a88dfcd69f2df94f3bf865f67c251168e897507921b7fe31a3f1376c404e8c3a0f67"
    $a9="1b99a6598299e157490ac8e5f71b5254b3a01796a03aa11e0dad34d1bc69a3b080ba58695cd88d49f17ff855035647d964d1617bbb38dd693adb0b0953e75b9e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}