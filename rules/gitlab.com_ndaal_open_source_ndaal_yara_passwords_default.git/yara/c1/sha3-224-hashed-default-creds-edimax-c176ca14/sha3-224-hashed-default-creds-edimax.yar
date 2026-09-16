rule sha3_224_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="57755ee7035a7a79d54949ecafc8008e8ddfdec3eeb772d8bf29639e"
    $a7="3587e29be301e57365b0e6c8b86d87743fe201e2eaee444a2d5baab2"
    $a8="74e9e35306cb170b41b514726cc07b9017456d0800f2fbd5287a20d8"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="2ac987e909b0366ffab85db5ffc160ddab2fde07d9fd9378b6cdbff9"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a13="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}