rule sha3_224_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a1="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a2="1aeed8455c7e500203c3680c8de04da20829722f02fa56643fde33a1"
    $a3="2a69c0da1a8a203108e7dafdc18d206230bfdadb4e25961c748375cd"
    $a4="3d2465a3f806df2b6ac34f58dae5021a32a0c5b4da45dfcea130aaab"
    $a5="514bd8a2a12d978f367c7f70551e6688af3d72a89997907389df5ef2"
    $a6="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a7="e810597249305f414f75eb5a9d2644820de439bc4647bbbdd90f702d"
    $a8="0452aba97190537aa9211a1911b2384fc81a7f013238c0ef118f6284"
    $a9="f026fbe9c452b660835b33a6c813366b5495c908a46a5449abb4f9cd"
    $a10="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}