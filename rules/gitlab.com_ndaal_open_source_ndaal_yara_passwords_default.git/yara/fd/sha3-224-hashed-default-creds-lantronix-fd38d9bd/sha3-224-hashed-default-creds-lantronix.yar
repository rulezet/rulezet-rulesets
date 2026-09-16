rule sha3_224_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a1="1b80ba673a959ff153aa35c0bcf7bbc66aee780c7680fbb15a445c3a"
    $a2="44dce7e29c53baf26f62ba8fb762fa83014db48740a391cc97a16b7f"
    $a3="b3c613fcea10ca76dab2bae1ff0054b92d46aead56580e60898b6f82"
    $a4="a86118aed12772c63e1641003f22dadc2be7ee74d4cb33aeb0b3466d"
    $a5="0509e9a858996f62da0f676687a1e2b209ed07819cd43f3021981b38"
    $a6="44dce7e29c53baf26f62ba8fb762fa83014db48740a391cc97a16b7f"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}