rule sha3_224_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2c897a235aaeac2fc0ccc1fe8bbae4196a2048cc30dde6208c25cf9"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="b2c897a235aaeac2fc0ccc1fe8bbae4196a2048cc30dde6208c25cf9"
    $a3="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
    $a4="978ef02bb6885624beb66a3c76cbf1aef4195e07dfbfa7aa1013e853"
    $a5="c125ce68f583ea1fabec8152c54d60d14131a6f037cb0ce85605e7fa"
    $a6="978ef02bb6885624beb66a3c76cbf1aef4195e07dfbfa7aa1013e853"
    $a7="448c754a66d168b6d4b8f739c975a6c92d0fe8b6a9fbc8b303e0f18c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}