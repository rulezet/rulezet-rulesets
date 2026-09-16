rule sha3_224_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="026727ec105a060b02a0086a2181748f6b9ac3cea3fc347ca8675984"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="e75cf98e6e8fc6775e99d9d2563f172f1855b3f1788c9a7db0932704"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a7="b158b1d74cf4c3c13d914034055183bad8697f81868ba01cf9c656ab"
    $a8="56279de09aff6b05fc30a9e345a3602f03b12fbcc48b3f21bf76cbf6"
    $a9="56279de09aff6b05fc30a9e345a3602f03b12fbcc48b3f21bf76cbf6"
    $a10="aa37e818a70652b92859f6fcb4a017e719f83d07039457447c61037b"
    $a11="aa37e818a70652b92859f6fcb4a017e719f83d07039457447c61037b"
    $a12="a9ae02a96da3643414ad2a9fb3d76d6a6d441c84f745edf5e0aea1c7"
    $a13="1bbdd3ab361d7fd9a47de72543e337093aaa664a02248557615675c4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}