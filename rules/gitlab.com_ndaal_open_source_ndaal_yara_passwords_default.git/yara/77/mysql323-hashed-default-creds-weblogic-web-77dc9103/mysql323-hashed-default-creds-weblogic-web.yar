rule mysql323_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05d42dcd1be2656d"
    $a1="05d42dcd1be2656d"
    $a2="5d2e19393cc5ef67"
    $a3="62068042172418e8"
    $a4="5d2e19393cc5ef67"
    $a5="4297dfd67bfb01dd"
    $a6="56b6113a2cefc6ea"
    $a7="4297dfd67bfb01dd"
    $a8="44572efd7376b21c"
    $a9="44572efd7376b21c"
    $a10="5336eb751494bdb1"
    $a11="6a77f1277b51f67f"
    $a12="2b50114e7dd56ee6"
    $a13="6a77f1277b51f67f"
    $a14="5d2e19393cc5ef67"
    $a15="6a77f1277b51f67f"
    $a16="33199d1c16cb58f3"
    $a17="6a77f1277b51f67f"
    $a18="56b6113a2cefc6ea"
    $a19="56b6113a2cefc6ea"
    $a20="4a2c3cfa4d988a0a"
    $a21="4a2c3cfa4d988a0a"
    $a22="60a7f6c73c50e3b1"
    $a23="56b6113a2cefc6ea"
    $a24="33199d1c16cb58f3"
    $a25="56b6113a2cefc6ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}