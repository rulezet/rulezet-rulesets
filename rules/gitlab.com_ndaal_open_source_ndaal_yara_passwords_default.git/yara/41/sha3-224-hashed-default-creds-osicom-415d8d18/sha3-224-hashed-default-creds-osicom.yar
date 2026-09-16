rule sha3_224_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a1="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a2="0ead148441198813f78304269fe89dd5dbca5d603121029b54b118c0"
    $a3="5122338bd461aecad5e9cd8266c965d6068c3a17e6283d041e4d4627"
    $a4="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a6="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a7="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a8="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a9="0ead148441198813f78304269fe89dd5dbca5d603121029b54b118c0"
    $a10="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a11="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a12="a2fcd96462d82e1cd53d6b2dba8fc00c31d68b15f50b0aebb5c99b13"
    $a13="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a14="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a15="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a16="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a17="019a9dcdc46bf97d8b6e7e402792c3089e3a24a2f5466f34bc285a1e"
    $a18="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a19="806a92f9d22571e07f91514b82e6cdd119bcbb2ec4b8def3c5717044"
    $a20="c4ac0665fbc37a1b5e7028ce9352ac05e972e1e115d5bced500f0de2"
    $a21="96eefd676a924762c32e5a05ce00ac80105c9c362c9dc0af613573d5"
    $a22="5f5c82ceba48805254828ca4c8e61e236fd9d04d948e5f05169d35a4"
    $a23="061f8e291064d95e8c1dbd1a6f90bfd2ebf5a90150f9e36cd8529eb9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}