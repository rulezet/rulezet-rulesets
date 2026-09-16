rule sha3_224_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4b9c404bba7e23ae6e86dc8260931e016f4f066fb6f80036fd78712a"
    $a1="4b9c404bba7e23ae6e86dc8260931e016f4f066fb6f80036fd78712a"
    $a2="70d8652689d23882313799bd223a16b9f2d17ddd5997c5fdbd488bf7"
    $a3="70d8652689d23882313799bd223a16b9f2d17ddd5997c5fdbd488bf7"
    $a4="dcf22cc69e63a23360f92909d477a244cc6e351e0253a4c8a0f9cf51"
    $a5="0b6439424fdc07128efc5abb505eb04bfcd556032bae9e8bca95824b"
    $a6="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a7="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}