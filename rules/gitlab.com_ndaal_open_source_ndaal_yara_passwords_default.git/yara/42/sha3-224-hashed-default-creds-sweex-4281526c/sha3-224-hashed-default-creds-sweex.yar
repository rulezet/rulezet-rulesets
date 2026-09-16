rule sha3_224_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21c3945f6418df7177b27fbc54bd27f12cb7e8633f2b28044008de2c"
    $a1="632320d4c1e678748f6314f75686d47ab31ec31457fbf307f995ca97"
    $a2="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="74e9e35306cb170b41b514726cc07b9017456d0800f2fbd5287a20d8"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="23d8138b9b97353676e81615f06e359497faca5a0224548a34e7ab6d"
    $a7="23d8138b9b97353676e81615f06e359497faca5a0224548a34e7ab6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}