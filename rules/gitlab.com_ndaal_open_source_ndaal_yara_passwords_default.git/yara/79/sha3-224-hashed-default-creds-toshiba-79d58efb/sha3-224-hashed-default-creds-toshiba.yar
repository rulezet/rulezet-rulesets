rule sha3_224_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a1="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a2="6be790258b73da9441099c4cb6aeec1f0c883152dd74e7581b70a648"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="dd4a9f71ed6e86954d93830442061c4dc17b9180a7055d1092d1511e"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="3ed054654392c1c523083b2a6901e20d9044728afb1868e9233fee31"
    $a7="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}