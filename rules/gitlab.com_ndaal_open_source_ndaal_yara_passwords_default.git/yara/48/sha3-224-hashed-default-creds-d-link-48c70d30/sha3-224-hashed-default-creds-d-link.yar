rule sha3_224_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="2e3cbc64ac7ed7c82b5ddb5ba5b4211b1b3517f80d0ccd1018b3f46a"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="45892c5692ace56b005ca7e1db951ba6a8c98ac2ff1af2f13eef5913"
    $a9="5ff358742a8d0bdc1c5ef08f8093046e39f5dc137d53ad1add310d34"
    $a10="fce6b65ff1f6bdf9a6f0aacd5e7a9dc7644d73363d611da652b343ef"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="a2e1b6c323964b309ab92c1cbe0bb01b83f5fbb9920546bcd09d2fac"
    $a13="a2e1b6c323964b309ab92c1cbe0bb01b83f5fbb9920546bcd09d2fac"
    $a14="2f58f74ee10c605ee49ffb90102ed51bfc141dd508b9e301815cce04"
    $a15="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a16="0ad7e7f649086006c9f036e85b191d1d4fead179a27848e0deede101"
    $a17="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a18="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a19="b3c364c455fdc02ee1d0a45cf07e428e2473fd969fdfc4d659d3a285"
    $a20="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a21="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}