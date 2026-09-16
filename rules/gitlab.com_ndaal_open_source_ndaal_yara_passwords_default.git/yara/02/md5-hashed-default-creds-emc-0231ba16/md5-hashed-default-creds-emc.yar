rule md5_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cb9c8a8048fd02294477fcb1a41191a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="1a9dff15f98150442174271a223d01e4"
    $a3="7ee9752b2cc8cf79166873da134ac761"
    $a4="039f2bacad245a359cc88f43bf4bbd3f"
    $a5="5da987473973a996f303dccfa308160f"
    $a6="4cb9c8a8048fd02294477fcb1a41191a"
    $a7="37de24d440285a58d86e6839a3eb2acd"
    $a8="048c21b71137ad978860b7e67e5f69c0"
    $a9="6400fdef8b87edde46714578f8b5a872"
    $a10="c95c36daa17296c6317f3fc675de3608"
    $a11="c28982f5264217c9acfab23147befe30"
    $a12="0784aa5865d8fbff51a2add45f9de052"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="4cb9c8a8048fd02294477fcb1a41191a"
    $a15="63a9f0ea7bb98050796b649e85481845"
    $a16="6853d501d96f6bf1e2529ea67f233239"
    $a17="b1c5be98d7e88c196478a195bd9cc934"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}