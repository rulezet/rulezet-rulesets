rule sha3_224_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30c04cbad71a234a295ef6445ce18fbf2e39b83e054b93e6030e305c"
    $a1="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="ef7288e18476c5b2efb6d043e4bd7f5d955df401618360641761f6dd"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a7="9623c659c62f27f089236dfc7dee913d0ac0c1539cb396341e9ea72a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}