rule blake2s_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b04fb84e0aa0e13d168788ed66723f8c7e33a61e373eb06ef99e9abc2beaf43f"
    $a1="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a2="326a7d2cd8a336fbc3878baf1a04f0ed954ab91c94fc4dc4b74729ed68d4d9e3"
    $a3="34f5e5e28f39b758f8ef27a17724b191dc497e8b0b36d17a72aac98e36b576c3"
    $a4="326a7d2cd8a336fbc3878baf1a04f0ed954ab91c94fc4dc4b74729ed68d4d9e3"
    $a5="5c50e191819ff413748babed9a676dda695c15e8782f91e097df1270ad8de052"
    $a6="51409de7ad1370d5627c5661929c84eef6b08adf9f59280c59b44fff06fbdda1"
    $a7="6fbdca481f278ddc7f88d56e9f6e017e55d36c39f65ea1b0de9a3fd6e79974de"
    $a8="406f0ed7696a6cb6cb457b6fdd8fa62e895d8e35e1670c454217ff91ad887a25"
    $a9="406f0ed7696a6cb6cb457b6fdd8fa62e895d8e35e1670c454217ff91ad887a25"
    $a10="b09da05e04eed57dba48ef2735480a2890291392d192e7fcc5d13c0c411ab135"
    $a11="b73d8fb89e3e4769176f578c30fe3b8b5c5fd11f8014c4633bfa4e33f08de540"
    $a12="252635526fda32206f835dd6c0ea42cc80ba5b4ab4dfeaffbb494fe24498e010"
    $a13="252635526fda32206f835dd6c0ea42cc80ba5b4ab4dfeaffbb494fe24498e010"
    $a14="aa605078e1d730da3720365b2ab000c4db9407b05e22accf60daabbde552abdf"
    $a15="f6dc614f47820b7a8a201f096ed59784438bc66a9e5449bdb4e6f47eafb20cfe"
    $a16="e52425250b93ac717b41a15a15a865757fa64c9dbd228cfa3702cd858b3fe3d9"
    $a17="e52425250b93ac717b41a15a15a865757fa64c9dbd228cfa3702cd858b3fe3d9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}