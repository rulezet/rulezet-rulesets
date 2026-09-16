rule md5_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fff2655621de957b18b6d82bbf501ac"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="5080a45f679bdec54b95a9be52874ce7"
    $a3="fb597942b9bc0e4da63896d0fd97a93c"
    $a4="3848f2bc4fc05feb35f5291a336fa4be"
    $a5="084e0343a0486ff05530df6c705c8bb4"
    $a6="265b6ae9e12b815dd5249983fa30d04b"
    $a7="0acde3887f89351a3854282fe899139c"
    $a8="5374e956c883bc2604b62f94bfb59e66"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="21232f297a57a5a743894a0e4a801fc3"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="879ca5388547df3d90724a84ef50db94"
    $a13="b2e0af57b9494f497d147224117005f9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}