rule sha3_224_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a3="5413432a9c301397e5b5ddb212b7b413a4c97f48c0dafb32a0e8e166"
    $a4="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a5="9f4cd298b8d6a29d017fd5990c22c328c5470eaa887fc1d8bbb65d1d"
    $a6="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a7="f6686c0af609bade2b79d70747f7ffb4aadc77c08d48fe292c28585f"
    $a8="cafc7b1bce7fad90c07fb9e2fc3d44a4dc479b7d9177be07988ed776"
    $a9="9df3cc4f1160675adba0ba283c103037e3b3210c7cfd697bc27f8821"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}