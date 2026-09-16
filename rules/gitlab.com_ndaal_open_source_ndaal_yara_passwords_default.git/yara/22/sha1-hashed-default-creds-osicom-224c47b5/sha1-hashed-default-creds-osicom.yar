rule sha1_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a1="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a2="55089334dd9c7803537f7351ea6b9a11a77432f9"
    $a3="32faaecac742100f7753f0c1d0aa0add01b4046b"
    $a4="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a6="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a7="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a8="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a9="55089334dd9c7803537f7351ea6b9a11a77432f9"
    $a10="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a11="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a12="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a13="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a14="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a15="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a16="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a17="babe3050e2e81dfd87a8ce67264d518cb34aef72"
    $a18="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a19="b2d21e771d9f86865c5eff193663574dd1796c8f"
    $a20="c399e65b00aa8b0afde3a8b35acc947d82846057"
    $a21="7841fb1f92b99194ca818d410cb09430731b6285"
    $a22="e80721793c24ae14edfca9b26ad406a9815cd3ff"
    $a23="e1d0c6c1c29e6ad5164072a5b21340dca7fcb052"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}