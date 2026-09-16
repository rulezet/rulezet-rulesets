rule sha1_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bebc72a97f354b6ab29e66121c7c601b28600211"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="70f6d48f94ce3e7636bbf4744ac074509d670e6f"
    $a3="2a71782810af38f2562a8bdc655b254358d41456"
    $a4="748a62ba53131f7f8dbbfde2da56163a66013b85"
    $a5="3f8f000fed900c4a189a93ce4858281bfb370f09"
    $a6="3ba6bee8653e48a9945a667ab7357beb0c0ef4c5"
    $a7="a5b23f338648cb6f21e2cc1284e4d1b7b930ac97"
    $a8="3c3e51590a3678f06e867bc4a8dab221fc45f2e8"
    $a9="ad9a978fec29fc8a566a4aca31b197f6c9f2c1ca"
    $a10="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
    $a11="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
    $a12="67ea18171ee2c51ce8672fe519a2e9d7ed09916b"
    $a13="6eb0c61201a96afc99cbf180f1c8d93c0a9fd8c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}